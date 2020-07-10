#include "enclave/enclave_util.h"
#include "enclave/lthread.h"

#include <link.h>

#include <stdarg.h>

#include "openenclave/corelibc/oemalloc.h"
#include "openenclave/corelibc/oestring.h"
#include "openenclave/internal/print.h"
#ifdef DEBUG
#include "openenclave/internal/backtrace.h"
#endif

#define OE_STDERR_FILENO 1

void sgxlkl_fail(const char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] FAIL: ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);

#ifdef DEBUG
    lthread_dump_all_threads();
#endif

    oe_abort();
}

void sgxlkl_error(const char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] ERROR: ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
}

void sgxlkl_warn(const char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] WARN: ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
}

void sgxlkl_info(const char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
}

void* oe_malloc_or_die(size_t size, const char* fail_msg, ...)
{
    va_list(args);
    va_start(args, fail_msg);

    void* ptr = oe_malloc(size);
    if (ptr == NULL)
    {
        sgxlkl_fail(fail_msg, args);
    }
    return ptr;
}

void* oe_calloc_or_die(size_t nmemb, size_t size, const char* fail_msg, ...)
{
    va_list(args);
    va_start(args, fail_msg);

    void* ptr = oe_calloc(nmemb, size);
    if (ptr == NULL)
    {
        sgxlkl_fail(fail_msg, args);
    }
    return ptr;
}

#ifdef DEBUG

#include <config.h>

#include <bfd.h>

typedef struct
{
    void* address;
    const char* file;
    ElfW(Addr) base;
} match_t;

static int dl_iterate_phdr_cb(
    struct dl_phdr_info* info,
    size_t size,
    void* data)
{
    match_t* match = (match_t*)data;

    for (size_t i = 0; i < info->dlpi_phnum; i++)
    {
        const ElfW(Phdr)* phdr = &info->dlpi_phdr[i];

        if (phdr->p_type == PT_LOAD)
        {
            ElfW(Addr) vaddr = phdr->p_vaddr + info->dlpi_addr;
            ElfW(Addr) maddr = (ElfW(Addr))match->address;
            if ((maddr >= vaddr) && (maddr < vaddr + phdr->p_memsz))
            {
                match->file = info->dlpi_name;
                match->base = info->dlpi_addr;
                return 1;
            }
        }
    }
    return 0;
}

static char** process_file(const char* fileName, bfd_vma* addr, int naddr)
{
    bfd* abfd = bfd_openr(fileName, NULL);
    if (!abfd)
    {
        printf("Error opening bfd file \"%s\"\n", fileName);
        return NULL;
    }

    if (bfd_check_format(abfd, bfd_archive))
    {
        printf("Cannot get addresses from archive \"%s\"\n", fileName);
        bfd_close(abfd);
        return NULL;
    }

    char** matching;
    if (!bfd_check_format_matches(abfd, bfd_object, &matching))
    {
        printf("Format does not match for archive \"%s\"\n", fileName);
        bfd_close(abfd);
        return NULL;
    }

    // asymbol** syms = kstSlurpSymtab(abfd, fileName);
    // if (!syms)
    // {
    //     printf("Failed to read symbol table for archive \"%s\"\n", fileName);
    //     bfd_close(abfd);
    //     return NULL;
    // }

    // char** retBuf = translateAddressesBuf(abfd, addr, naddr, syms);

    // oe_free(syms);

    bfd_close(abfd);
    // return retBuf;
    return NULL;
}

static char** backtrace_symbols(void* const* addresses, size_t num_addresses)
{
    bfd_init();

    char*** locations = (char***)malloc(sizeof(char**) * num_addresses);
    int num_string_bytes = 0;
    for (size_t i = 0; i < num_addresses; i++)
    {
        match_t match = {0};
        dl_iterate_phdr(&dl_iterate_phdr_cb, &match);

        // adjust the address in the global space of your binary to an
        // offset in the relevant library
        bfd_vma addr = (bfd_vma)(addresses[i]);
        addr -= (bfd_vma)(match.base);

        // lookup the symbol
        if (match.file && oe_strlen(match.file))
            locations[i] = process_file(match.file, &addr, 1);
        else
            locations[i] = process_file("/proc/self/exe", &addr, 1);

        num_string_bytes += oe_strlen(locations[i][0]) + 1;
    }

    char** final =
        (char**)oe_malloc(num_string_bytes + (num_addresses * sizeof(char*)));
    char* f_strings = (char*)(final + num_addresses);

    for (size_t i = 0; i < num_addresses; i++)
    {
        size_t len = oe_strlen(locations[i][0]);
        memcpy(f_strings, locations[i][0], len + 1);
        oe_free(locations[i]);
        final[i] = f_strings;
        f_strings += len + 1;
    }

    oe_free(locations);

    return final;
}

/**
 * Provide access to an internal OE function. We cannot use the public
 * oe_backtrace function because we need to pass in custom frame pointers of
 * other lthreads.
 */
extern int oe_backtrace_impl(void** start_frame, void** buffer, int size);

void sgxlkl_print_backtrace(void** start_frame)
{
    void* buf[256];
    size_t size;
    char** strings;
    size_t i;

    size = oe_backtrace_impl(
        start_frame == NULL ? __builtin_frame_address(0) : start_frame,
        buf,
        sizeof(buf));
    strings = oe_backtrace_symbols(buf, size);

    strings = backtrace_symbols(buf, size);

    for (i = 0; i < size; i++)
        sgxlkl_info("    #%ld: %p in %s(...)\n", i, buf[i], strings[i]);

    oe_free(strings);
}
#endif

uint64_t next_power_of_2(uint64_t n)
{
    uint64_t power_of_2 = 1;
    while (power_of_2 < n)
        power_of_2 = power_of_2 << 1;
    return power_of_2;
}