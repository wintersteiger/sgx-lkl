/*
 * Lthread
 * Copyright (C) 2012, Hasan Alayli <halayli@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * lthread.h
 */


#ifndef LTHREAD_H
#define LTHREAD_H

#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

#include "sgx_enclave_config.h"
#include "sgx_hostcall_interface.h"
#include "locale_impl.h"
#include "atomic.h"
#include "queue.h"
#include "tree.h"

#define DEFINE_LTHREAD (lthread_set_funcname(__func__))
#define CLOCK_LTHREAD CLOCK_REALTIME

struct mpmcq __scheduler_queue;

typedef void *(*lthread_func)(void *);

struct cpu_ctx {
    void     *esp;
    void     *ebp;
    void     *eip;
    void     *edi;
    void     *esi;
    void     *ebx;
    void     *r1;
    void     *r2;
    void     *r3;
    void     *r4;
    void     *r5;
};

enum lthread_st {
    LT_ST_NEW,          /* lthread spawned but needs initialization */
    LT_ST_READY,        /* lthread is ready to run */
    LT_ST_EXITED,       /* lthread has exited and needs cleanup */
    LT_ST_BUSY,         /* lthread is waiting on join/cond/compute/io */
    LT_ST_SLEEPING,     /* lthread is sleeping */
    LT_ST_EXPIRED,      /* lthread has expired and needs to run */
    LT_ST_DETACH,       /* lthread frees when done, else it waits to join */
    LT_ST_CANCELLED,    /* lthread has been cancelled */
    LT_ST_CANCELSTATE,    /* lthread cancellation has been disabled */
    LT_ST_CANCEL_DISABLED,     /* lthread cancellation has been deferred */
    LT_ST_PINNED, /* lthread pinned to ethread */
};

struct lthread_tls {
    pthread_key_t key;
    void *data;
    LIST_ENTRY(lthread_tls) tls_next;
};
LIST_HEAD(lthread_tls_l, lthread_tls);

struct lthread_tls_destructors {
    pthread_key_t key;
    void (*destructor)(void*);
    LIST_ENTRY(lthread_tls_destructors) tlsdestr_next;
};
LIST_HEAD(lthread_tlsdestr_l, lthread_tls_destructors);

struct lthread_attr {
    size_t                  stack_size;      /* current stack_size */
    int                     state;           /* current lthread state */
    void                    *stack;          /* ptr to lthread_stack */
};

typedef void (* sig_handler) (int sig, siginfo_t *si, void *unused);

/*
 * a simple struct describing an existing futex. It is not safe to use malloc
 * and/or free while holding the futex ticketlock as both malloc and free
 * perform a futex system call themselves under certain circumstances which will
 * result in a deadlock.
 *
 * We therefore have an fq field in the lthread struct.
 */
struct futex_q {
    uint32_t futex_key;
    uint32_t futex_bitset;
    uint64_t futex_deadline;
    clock_t clock;
    struct lthread *futex_lt;

    SLIST_ENTRY(futex_q) entries;
};

struct lthread {
    struct cpu_ctx          ctx;            /* cpu ctx info */
    lthread_func            fun;            /* func lthread is running */
    void                    *arg;           /* func args passed to func */
    size_t                  syscall;        /* slot for syscalls */
    Arena                   syscallarena;   /* syscall buffer arena */
    struct lthread_attr     attr;           /* various attributes */
    struct __ptcb           *cancelbuf;     /* cancellation buffer */
    int                     tid;            /* lthread id */
    char                    funcname[64];   /* optional func name */
    struct lthread          *lt_join;       /* lthread we want to join on */
    void                    **lt_exit_ptr;  /* exit ptr for lthread_join */
    locale_t                locale;         /* locale of current lthread */
    uint32_t                ops;            /* num of ops since yield */
    uint64_t                sleep_usecs;    /* how long lthread is sleeping */
    FILE*                   stdio_locks;    /* locked files */
    struct lthread_tls_l    tls;            /* pointer to TLS */
    uint8_t                 *itls;          /* image TLS */
    size_t                  itlssz;         /* size of TLS image */
    RB_ENTRY(lthread)       sleep_node;     /* sleep tree node pointer */
    int err;                                /* errno value */
    char *dlerror_buf;
    int dlerror_flag;
    uintptr_t *dtv;
    uintptr_t *dtv_copy;
    /* yield_cb_* are a callback to call after yield finished and it's arg */
    /* they are required to release futex lock on FUTEX_WAIT operation */
    /* and in sched_yield (see comment there) to avoid race among schedulers */
    void                    (*yield_cb)(void*);
    void                    *yield_cbarg;
    struct futex_q fq;
    struct {
        volatile void *volatile head;
        long off;
        volatile void *volatile pending;
    } robust_list;
};

struct lthread_queue {
    struct lthread *lt;
    struct lthread_queue *next;
};

RB_HEAD(lthread_rb_sleep, lthread);

LIST_HEAD(lthread_l, lthread);
TAILQ_HEAD(lthread_q, lthread);

struct lthread_sched {
    struct cpu_ctx      ctx;
    void                *stack;
    size_t              stack_size;
    uint64_t            default_timeout;
    int                 page_size;
    size_t              syscall;
    Arena               arena;
    /* convenience data maintained by lthread_resume */
    struct lthread      *current_lthread;
    size_t              current_syscallslot;
    Arena               *current_arena;
};

typedef struct lthread *lthread_t;
#ifdef __cplusplus
extern "C" {
#endif

    void    lthread_sched_global_init(size_t sleepspins, size_t sleeptime_ns, size_t futex_wake_spins);
    int     lthread_create(struct lthread **new_lt, struct lthread_attr *attrp, void *lthread_func, void *arg);
    void    lthread_cancel(struct lthread *lt);
    void    lthread_run(void);
    int     lthread_join(struct lthread *lt, void **ptr, uint64_t timeout);
    void    lthread_detach(void);
    void    lthread_detach2(struct lthread *lt);
    void    lthread_exit(void *ptr);
    //void    lthread_sleep(uint64_t msecs);
    void    lthread_wakeup(struct lthread *lt);
    int     lthread_init(size_t size);
    struct lthread *lthread_current();
    void    lthread_set_funcname(struct lthread *lt, const char *f);
    uint64_t lthread_id();
    struct lthread* lthread_self(void);
    int     lthread_setcancelstate(int, int*);
    void    lthread_set_expired(struct lthread *lt);

    static inline void __scheduler_enqueue(struct lthread *lt) {
        if (!lt) {a_crash();}
        for (;!mpmc_enqueue(&__scheduler_queue, lt);) a_spin();
    }

#ifdef __cplusplus
}
#endif

#endif
