#if defined(NATIVE_RUNNER)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

typedef unsigned int uint32_t;
typedef unsigned long uintptr_t;

static volatile unsigned slab_count;
static volatile unsigned mapping_count;

__attribute__((noinline, used, visibility("default"))) void slab_alloc(void) {
    slab_count++;
}

__attribute__((noinline, used, visibility("default"))) void mapping_alloc(void) {
    mapping_count++;
}

__attribute__((noinline, used, visibility("default"))) void kmalloc(void) {
    slab_alloc();
}

__attribute__((noinline, used, visibility("default"))) void vmalloc(void) {
    mapping_alloc();
}

__attribute__((noinline, used, visibility("default"))) long __x64_sys_fixture(unsigned long value) {
    if (value == 0x6b65726eU) kmalloc();
    return 0;
}

__attribute__((noinline, used, visibility("default"))) int entry_direct(uint32_t value) {
    if (value == 7) slab_alloc();
    return 0;
}

__attribute__((noinline)) static int wrapper(uint32_t value) {
    if (value == 0x2026) mapping_alloc();
    return 0;
}

__attribute__((noinline, used, visibility("default"))) int entry_wrapper(uint32_t value) {
    return wrapper(value);
}

__attribute__((noinline, used, visibility("default"))) int entry_conditional(uint32_t value) {
    if ((value & 0xffffffffU) == 0xc0ffee11U) mapping_alloc();
    return 0;
}

__attribute__((noinline, used, visibility("default"))) int entry_infeasible(uint32_t value) {
    if (value == 0x12345678U && value != 0x12345678U) slab_alloc();
    return 0;
}

__attribute__((noinline, used, visibility("default"))) int entry_loop(uint32_t value) {
    for (unsigned i = 0; i < (value & 15U); i++) {
        if (i == 7) slab_alloc();
    }
    return 0;
}

__attribute__((noinline, used, visibility("default"))) int entry_indirect(uint32_t value) {
    void (*volatile target)(void) = (value & 1U) ? slab_alloc : mapping_alloc;
    target();
    return 0;
}

__attribute__((noinline, used, visibility("default"))) int entry_unsupported(uint32_t value) {
    void (*volatile target)(void) = (void (*)(void))(uintptr_t)value;
    target();
    return 0;
}

__attribute__((noinline)) static int multi_inner(uint32_t value) {
    if (value == 0xC0FFEE11U) mapping_alloc();
    return 0;
}

__attribute__((noinline)) static int multi_outer(uint32_t value) {
    return multi_inner(value);
}

__attribute__((noinline, used, visibility("default"))) int entry_multi_route(uint32_t value) {
    if (value == 0xC0FFEE11U && value != 0xC0FFEE11U) mapping_alloc();
    return multi_outer(value);
}

__attribute__((noinline, used, visibility("default"))) int entry_correlated(uint32_t left, uint32_t right) {
    if ((left == 7U && right == 11U) || (left == 13U && right == 17U)) mapping_alloc();
    return 0;
}

#if defined(NATIVE_RUNNER)
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    uint32_t value = (uint32_t)strtoul(argv[2], NULL, 0);
    if (strcmp(argv[1], "correlated") == 0) {
        if (argc != 4) return 2;
        entry_correlated(value, (uint32_t)strtoul(argv[3], NULL, 0));
    }
    else if (argc != 3) return 2;
    else if (strcmp(argv[1], "direct") == 0) entry_direct(value);
    else if (strcmp(argv[1], "wrapper") == 0) entry_wrapper(value);
    else if (strcmp(argv[1], "conditional") == 0) entry_conditional(value);
    else if (strcmp(argv[1], "infeasible") == 0) entry_infeasible(value);
    else if (strcmp(argv[1], "loop") == 0) entry_loop(value);
    else if (strcmp(argv[1], "indirect") == 0) entry_indirect(value);
    else if (strcmp(argv[1], "multi-route") == 0) entry_multi_route(value);
    else return 2;
    printf("{\"slab\":%u,\"mapping\":%u}\n", slab_count, mapping_count);
    return 0;
}
#endif
