#include <enclave/oe_compat.h>

#define OE_BUILD_ENCLAVE
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/eeid_attester.h>
#include <openenclave/attestation/sgx/eeid_plugin.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/eeid.h>
#include <openenclave/internal/globals.h>

#include "enclave/enclave_oe.h"
#include "enclave/enclave_signal.h"
#include "enclave/enclave_util.h"
#include "shared/env.h"

const sgxlkl_enclave_config_t* sgxlkl_enclave = NULL;
sgxlkl_enclave_state_t sgxlkl_enclave_state = {0};

bool sgxlkl_in_sw_debug_mode()
{
    return sgxlkl_enclave_state.config->mode == SW_DEBUG_MODE;
}

bool sgxlkl_in_hw_debug_mode()
{
    return sgxlkl_enclave_state.config->mode == HW_DEBUG_MODE;
}

bool sgxlkl_in_hw_release_mode()
{
    return sgxlkl_enclave_state.config->mode == HW_RELEASE_MODE;
}

static void prepare_elf_stack()
{
    sgxlkl_enclave_state_t* state = &sgxlkl_enclave_state;
    const sgxlkl_enclave_config_t* cfg = state->config;

    // import host envp
    state->num_imported_env = 0;
    state->imported_env = NULL;

    if (sgxlkl_enclave_state.shared_memory.env && cfg->num_host_import_env > 0)
    {
        state->imported_env = malloc(sizeof(char*) * cfg->num_host_import_env);
        if (!state->imported_env)
            sgxlkl_fail("Could not allocate memory for imported host environment\n");

        for (size_t i = 0; i < cfg->num_host_import_env; i++)
        {
            const char* name = cfg->host_import_env[i];
            for (char* const* p = sgxlkl_enclave_state.shared_memory.env;
                 p && *p != NULL;
                 p++)
            {
                size_t n = strlen(name);
                if (strncmp(name, *p, n) == 0 && (*p)[n] == '=')
                {
                    const char* str = *p;
                    size_t len = strlen(str);
                    char* cpy = malloc(len + 1);
                    if (!cpy)
                        sgxlkl_fail("out of memory\n");
                    memcpy(cpy, str, len + 1);
                    state->imported_env[state->num_imported_env++] = cpy;
                }
            }
        }
    }

    size_t total_size = 0;
    size_t total_count = 1;
    for (size_t i = 0; i < cfg->num_args; i++)
        total_size += strlen(cfg->args[i]) + 1;
    total_count += cfg->num_args + 1;
    for (size_t i = 0; i < cfg->num_env; i++)
        total_size += strlen(cfg->env[i]) + 1;
    total_count += cfg->num_env + 1;
    for (size_t i = 0; i < state->num_imported_env; i++)
        total_size += strlen(state->imported_env[i]) + 1;
    total_count += state->num_imported_env + 1;
    total_count += 1; // auxv terminator
    total_count += 1; // platform-independent stuff terminator

    char* buf = calloc(total_size, sizeof(char));
    char** out = calloc(total_count, sizeof(char*));

    size_t j = 0;
    char* buf_ptr = buf;

#define ADD_STRING(S)               \
    {                               \
        size_t len = strlen(S) + 1; \
        memcpy(buf_ptr, (S), len);  \
        out[j++] = buf_ptr;         \
        buf_ptr += len;             \
    }

    elf64_stack_t* stack = &sgxlkl_enclave_state.elf64_stack;

    // argv
    stack->argv = out;
    for (size_t i = 0; i < cfg->num_args; i++)
        ADD_STRING(cfg->args[i]);
    stack->argc = j;
    out[j++] = NULL;

    // envp
    stack->envp = out + j;
    for (size_t i = 0; i < cfg->num_env; i++)
        ADD_STRING(cfg->env[i]);
    for (size_t i = 0; i < state->num_imported_env; i++)
        // Is this the right order for imported vars?
        ADD_STRING(state->imported_env[i]);
    out[j++] = NULL;

    // auxv
    stack->auxv = (Elf64_auxv_t**)(out + j);
    for (size_t i = 0; i < cfg->num_auxv; i++)
    {
        out[j++] = (char*)cfg->auxv[i].a_type;
        out[j++] = (char*)cfg->auxv[i].a_un.a_val;
    }
    out[j++] = NULL;

    // TODO: platform independent things?
    out[j++] = NULL;

    // CHECK: should the memory holding the strings also be on the stack?
}

// Header file for this doesn't get installed. Should OE initialize the
// verifier plugin automatically, when it receives a verification request?
oe_result_t oe_sgx_eeid_verifier_initialize(void);

static void _get_attestation_evidence()
{
    static const oe_uuid_t format_id = {OE_FORMAT_UUID_SGX_EEID_ECDSA_P256};

    oe_sgx_eeid_attester_initialize();
    oe_sgx_eeid_verifier_initialize();

    size_t evidence_buffer_size = 0;
    uint8_t* evidence_buffer = NULL;
    size_t endorsements_buffer_size = 0;
    uint8_t* endorsements_buffer = NULL;

    oe_result_t result = oe_get_evidence(
        &format_id,
        NULL,
        0,
        NULL,
        0,
        &evidence_buffer,
        &evidence_buffer_size,
        &endorsements_buffer,
        &endorsements_buffer_size);

    if (result != OE_OK)
        sgxlkl_fail("Failed to retrieve attestation evidence: %d.\n", result);
    else
        sgxlkl_info("Successfully obtained attestation evidence\n");

    oe_sgx_eeid_attester_shutdown();

    // Note: Since we're using the feature/sgx-lkl-support branch, we can
    // only verify quotes created from that branch.
    // oe_claim_t* claims = NULL;
    // size_t claims_size = 0;

    // result = oe_verify_evidence(
    //     evidence_buffer,
    //     evidence_buffer_size,
    //     NULL,
    //     0,
    //     NULL,
    //     0,
    //     &claims,
    //     &claims_size);

    // if (result != OE_OK)
    //     sgxlkl_warn("Failed to verify attestation evidence\n");
    // else
    // {
    //     sgxlkl_info("Successfully verified attestation evidence\n");

    //     for (size_t i = 0; i < claims_size; i++)
    //     {
    //         size_t n = claims[i].value_size;
    //         char vs[2 * n + 1];
    //         bytes_to_hex(vs, sizeof(vs), claims[i].value, n);
    //         sgxlkl_info(
    //             "Attestation claim #%d: %s=%s\n", i, claims[i].name, vs);
    //     }
    // }

    oe_free_evidence(evidence_buffer);
    oe_free_endorsements(endorsements_buffer);
    // oe_free_claims(claims, claims_size);
}

// We need to have a separate function here
int __sgx_init_enclave()
{
    const sgxlkl_enclave_config_t* config = sgxlkl_enclave_state.config;
    _register_enclave_signal_handlers(config->mode);

    prepare_elf_stack();

    return __libc_init_enclave(
        sgxlkl_enclave_state.elf64_stack.argc,
        sgxlkl_enclave_state.elf64_stack.argv);
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
    _lthread_sched_init(sgxlkl_enclave_state.config->stacksize);
    lthread_run();

    return;
}

static int _read_eeid_config()
{
    const oe_eeid_t* eeid = (oe_eeid_t*)__oe_get_eeid();
    const char* config_json = (const char*)eeid->data;
    sgxlkl_enclave_state.libc_state = libc_not_started;

    sgxlkl_enclave_config_t* cfg = malloc(sizeof(sgxlkl_enclave_config_t));
    if (!cfg)
        sgxlkl_fail("out of memory, cannot allocate enclave config.\n");
    int r = sgxlkl_read_enclave_config(config_json, cfg, true);
    sgxlkl_enclave_state.config = cfg;
    return r;
}

static int _copy_shared_memory(const sgxlkl_shared_memory_t* shm)
{
    // Copy shared memory. Deep copy so the host can't change it?
    memcpy(
        &sgxlkl_enclave_state.shared_memory,
        shm,
        sizeof(sgxlkl_shared_memory_t));

    // This will be removed once shared memory and config have been
    // separated fully.
    sgxlkl_enclave = sgxlkl_enclave_state.config;

    return 0;
}

int sgxlkl_enclave_init(const sgxlkl_shared_memory_t* shared_memory)
{
    SGXLKL_ASSERT(shared_memory);

    memset(&sgxlkl_enclave_state, 0, sizeof(sgxlkl_enclave_state));
    sgxlkl_enclave_state.libc_state = libc_not_started;

#ifdef DEBUG
    sgxlkl_enclave_state.verbose = 0;
#endif

    if (true)
        _get_attestation_evidence();

    if (_read_eeid_config())
        return 1;

    if (_copy_shared_memory(shared_memory))
        return 1;

#ifdef DEBUG
    // Initialise verbosity setting, so SGXLKL_VERBOSE can be used from this
    // point onwards
    sgxlkl_enclave_state.verbose = sgxlkl_enclave_state.config->verbose;
#endif

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

void sgxlkl_free_enclave_state()
{
    sgxlkl_enclave_state_t* state = &sgxlkl_enclave_state;

    sgxlkl_free_enclave_config((sgxlkl_enclave_config_t*)state->config);
    state->config = NULL;

    state->num_imported_env = 0;
    free(state->imported_env);

    state->elf64_stack.argc = 0;
    free(state->elf64_stack.argv);
    free(state->elf64_stack.envp);
    free(state->elf64_stack.auxv);

    state->num_disk_state = 0;
    free(state->disk_state);

    state->libc_state = libc_not_started;
}
