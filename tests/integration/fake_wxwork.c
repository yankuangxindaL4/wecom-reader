/* A real process with synthetic key material; never opens real WeCom data. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#endif

#define BLOCK (4u * 1024u * 1024u)
#define ARENA (2u * BLOCK)

static unsigned char *allocate_arena(void) {
#ifdef _WIN32
    uintptr_t address;
    for (address = 0x20000000; address < 0x70000000; address += 0x1000000) {
        unsigned char *p = VirtualAlloc((void *)address, ARENA, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (p) return p;
    }
    return NULL;
#else
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef MAP_32BIT
    flags |= MAP_32BIT;
#endif
    void *p = mmap((void *)0x20000000, ARENA, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if ((uintptr_t)p + ARENA > UINT32_MAX) { munmap(p, ARENA); return NULL; }
    return p;
#endif
}

int main(int argc, char **argv) {
    unsigned char key[16];
    char hex[34];
    unsigned int value;
    size_t i;
    const char *mode = argc > 1 ? argv[1] : "hex";
    unsigned char *arena = allocate_arena();
    if (!arena) { fprintf(stderr, "low-address allocation failed\n"); return 2; }
    if (!fgets(hex, sizeof(hex), stdin) || strlen(hex) < 32) return 3;
    for (i = 0; i < 16; ++i) {
        if (sscanf(hex + 2*i, "%2x", &value) != 1) return 4;
        key[i] = (unsigned char)value;
    }
#ifndef _WIN32
    /* Only this disposable test process permits sibling CLI readers. */
    if (strcmp(mode, "denied") == 0) {
        if (prctl(PR_SET_DUMPABLE, 0) != 0) { perror("PR_SET_DUMPABLE"); return 5; }
    } else if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) != 0) {
        perror("PR_SET_PTRACER"); return 6;
    }
    prctl(PR_SET_NAME, "UIThread", 0, 0, 0);
#endif
    if (strcmp(mode, "struct") == 0) {
        uint32_t flag = 1, page_size = 4096;
        uint32_t holder = (uint32_t)(uintptr_t)(arena + BLOCK + 512);
        uint32_t object = (uint32_t)(uintptr_t)(arena + BLOCK + 1024);
        memcpy(arena + 128, &flag, 4);
        memcpy(arena + 132, &page_size, 4);
        memcpy(arena + 136, key, 16);
        memcpy(arena + 128 + 0x30, &holder, 4);
        memcpy((void *)(uintptr_t)(holder + 4), &object, 4);
        memcpy((void *)(uintptr_t)(object + 0x24), &page_size, 4);
    } else {
        size_t offset = strcmp(mode, "boundary") == 0 ? BLOCK - 10 : 128;
        arena[offset] = 'x'; arena[offset + 1] = '\'';
        memcpy(arena + offset + 2, hex, 32);
        arena[offset + 34] = '\'';
    }
    memset(hex, 0, sizeof(hex));
    puts("READY"); fflush(stdout);
    /* EOF on the parent's control pipe is a deterministic shutdown signal. */
    while (getchar() != EOF) {}
#ifdef _WIN32
    VirtualFree(arena, 0, MEM_RELEASE);
#else
    munmap(arena, ARENA);
#endif
    return 0;
}
