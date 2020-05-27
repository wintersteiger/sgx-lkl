#include <string.h>

#include "pthread_impl.h"

#include <openenclave/bits/eeid.h>
#include <openenclave/internal/globals.h>

#include "enclave/enclave_oe.h"
#include "enclave/enclave_signal.h"
#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_config.h"
#include "shared/env.h"
#include "shared/sgxlkl_app_config.h"
#include "shared/sgxlkl_config_json.h"

extern int sgxlkl_verbose;

extern _Atomic(enum sgxlkl_libc_state) __libc_state;

sgxlkl_config_t* sgxlkl_enclave = NULL;

sgxlkl_enclave_state_t sgxlkl_enclave_state;

// We need to have a separate function here
int __sgx_init_enclave()
{
    _register_enclave_signal_handlers(sgxlkl_enclave->mode);

    return __libc_init_enclave(
        sgxlkl_enclave_state.app_config->argc,
        sgxlkl_enclave_state.app_config->argv);
}

void sgxlkl_enclave_show_attribute(const void* sgxlkl_enclave_base)
{
    char enclave_size_str[10];

    size_t sgxlkl_enclave_size = __oe_get_enclave_size();
    size_t sgxlkl_enclave_heap_size = __oe_get_heap_size();

    size_uint64_to_str(sgxlkl_enclave_size, enclave_size_str, 10);

    SGXLKL_VERBOSE(
        "enclave base=0x%p size=%s\n", sgxlkl_enclave_base, enclave_size_str);

    memset(enclave_size_str, 0, sizeof(enclave_size_str));
    size_uint64_to_str(sgxlkl_enclave_heap_size, enclave_size_str, 10);
#ifdef DEBUG
    const void* sgxlkl_enclave_heap_base = __oe_get_heap_base();
    const void* sgxlkl_enclave_heap_end = __oe_get_heap_end();
    SGXLKL_VERBOSE(
        "enclave heap base=0x%p size=%s end=0x%p\n",
        sgxlkl_enclave_heap_base,
        enclave_size_str,
        sgxlkl_enclave_heap_end);
#endif
}

void sgxlkl_ethread_init(void)
{
    void* tls_page;
    __asm__ __volatile__("mov %%fs:0,%0" : "=r"(tls_page));

    struct sched_tcb_base* sched_tcb = (struct sched_tcb_base*)tls_page;
    sched_tcb->self = (void*)tls_page;

    size_t tls_offset = SCHEDCTX_OFFSET;
    sched_tcb->schedctx = (struct schedctx*)((char*)tls_page + tls_offset);

    /* Wait until libc has been initialized */
    while (__libc_state != libc_initialized)
    {
        a_spin();
    }

    /* Initialization completed, now run the scheduler */
    __init_tls();
    _lthread_sched_init(sgxlkl_enclave->stacksize);
    lthread_run();

    return;
}

int sgxlkl_enclave_init(const sgxlkl_config_t* config_on_host)
{
    SGXLKL_ASSERT(config_on_host);

    sgxlkl_verbose = 0;

#ifndef OE_WITH_EXPERIMENTAL_EEID
    if (!config_on_host->app_config_str)
    {
        // Make sure all configuration and state is held in enclave memory.
        if (sgxlkl_copy_config(config_on_host, &sgxlkl_enclave))
            return 1;
    }
    else
#endif
    {
        const oe_eeid_t* eeid = (oe_eeid_t*)__oe_get_eeid();
        const char* app_config_json = (const char*)eeid->data;

        if (sgxlkl_read_config_json(
                app_config_json,
                &sgxlkl_enclave_state.host_memory,
                &sgxlkl_enclave_state.app_config))
            return 1;

        // Copy shared memory
        for (size_t i = 0; i < sgxlkl_enclave_state.host_memory->num_disks; i++)
            sgxlkl_enclave_state.host_memory->disks[i].virtio_blk_dev_mem =
                config_on_host->disks[i].virtio_blk_dev_mem;

        memcpy(
            &sgxlkl_enclave_state.host_memory->shared_memory,
            &config_on_host->shared_memory,
            sizeof(sgxlkl_shared_memory_t));

        // This will be removed once shared memory and config have been
        // separated fully.
        sgxlkl_enclave = sgxlkl_enclave_state.host_memory;
    }

    // Initialise verbosity setting, so SGXLKL_VERBOSE can be used from this
    // point onwards
    sgxlkl_verbose = sgxlkl_enclave->verbose;

    SGXLKL_VERBOSE("enter\n");

    // Sanity checks
    SGXLKL_ASSERT(oe_is_within_enclave(&sgxlkl_enclave->mode, sizeof(int)));
    if (sgxlkl_enclave->num_disks > 0)
    {
        SGXLKL_ASSERT(oe_is_within_enclave(
            &sgxlkl_enclave->disks[0], sizeof(enclave_disk_config_t)));
    }

    void* tls_page;
    __asm__ __volatile__("mov %%fs:0,%0" : "=r"(tls_page));

    struct sched_tcb_base* sched_tcb = (struct sched_tcb_base*)tls_page;
    sched_tcb->self = (void*)tls_page;

    size_t tls_offset = SCHEDCTX_OFFSET;
    sched_tcb->schedctx = (struct schedctx*)((char*)tls_page + tls_offset);

    const void* sgxlkl_enclave_base = __oe_get_enclave_base();
    sgxlkl_enclave_show_attribute(sgxlkl_enclave_base);

    /* Indicate ongoing libc initialisation */
    __libc_state = libc_initializing;

    SGXLKL_VERBOSE("calling _dlstart_c()\n");
    _dlstart_c((size_t)sgxlkl_enclave_base);

    return __sgx_init_enclave();
}
