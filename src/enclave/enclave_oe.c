#include <enclave/oe_compat.h>

#include <string.h>

#include "pthread_impl.h"

#include <openenclave/bits/eeid.h>
#include <openenclave/internal/globals.h>

#include "enclave/enclave_oe.h"
#include "enclave/enclave_signal.h"
#include "enclave/enclave_util.h"
#include "shared/env.h"
#include "shared/read_enclave_config.h"

int sgxlkl_verbose = 1;

sgxlkl_enclave_config_t* sgxlkl_enclave = NULL;

sgxlkl_enclave_state_t sgxlkl_enclave_state = {0};

bool sgxlkl_in_sw_debug_mode()
{
    return sgxlkl_enclave_state.enclave_config->mode == SW_DEBUG_MODE;
}

// We need to have a separate function here
int __sgx_init_enclave()
{
    _register_enclave_signal_handlers(sgxlkl_enclave->mode);

    return __libc_init_enclave(
        sgxlkl_enclave_state.enclave_config->app_config.argc,
        sgxlkl_enclave_state.enclave_config->app_config.argv);
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
    while (sgxlkl_enclave_state.libc_state != libc_initialized)
    {
        a_spin();
    }

    /* Initialization completed, now run the scheduler */
    __init_tls();
    _lthread_sched_init(sgxlkl_enclave->stacksize);
    lthread_run();

    return;
}

static int _read_eeid_config(const sgxlkl_shared_memory_t* shm)
{
    const oe_eeid_t* eeid = (oe_eeid_t*)__oe_get_eeid();
    const char* config_json = (const char*)eeid->data;
    sgxlkl_enclave_state.libc_state = libc_not_started;

    if (sgxlkl_read_enclave_config(
            config_json, &sgxlkl_enclave_state.enclave_config))
        return 1;

    // Copy shared memory. Deep copy so the host can't change it?
    memcpy(
        &sgxlkl_enclave_state.shared_memory,
        shm,
        sizeof(sgxlkl_shared_memory_t));

    // This will be removed once shared memory and config have been
    // separated fully.
    sgxlkl_enclave = sgxlkl_enclave_state.enclave_config;

    return 0;
}

int sgxlkl_enclave_init(const sgxlkl_shared_memory_t* shared_memory)
{
    SGXLKL_ASSERT(shared_memory);

    memset(&sgxlkl_enclave_state, 0, sizeof(sgxlkl_enclave_state));
    sgxlkl_enclave_state.libc_state = libc_not_started;

    sgxlkl_verbose = 0;

    if (_read_eeid_config(shared_memory))
        return 1;

    // Initialise verbosity setting, so SGXLKL_VERBOSE can be used from this
    // point onwards
    sgxlkl_verbose = sgxlkl_enclave_state.enclave_config->verbose;

    SGXLKL_VERBOSE("enter\n");

    void* tls_page;
    __asm__ __volatile__("mov %%fs:0,%0" : "=r"(tls_page));

    struct sched_tcb_base* sched_tcb = (struct sched_tcb_base*)tls_page;
    sched_tcb->self = (void*)tls_page;

    size_t tls_offset = SCHEDCTX_OFFSET;
    sched_tcb->schedctx = (struct schedctx*)((char*)tls_page + tls_offset);

    const void* sgxlkl_enclave_base = __oe_get_enclave_base();
    sgxlkl_enclave_show_attribute(sgxlkl_enclave_base);

    /* Indicate ongoing libc initialisation */
    sgxlkl_enclave_state.libc_state = libc_initializing;

    SGXLKL_VERBOSE("calling _dlstart_c()\n");
    _dlstart_c((size_t)sgxlkl_enclave_base);

    return __sgx_init_enclave();
}
