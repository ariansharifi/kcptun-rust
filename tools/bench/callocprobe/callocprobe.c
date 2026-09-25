/*
 * callocprobe — how much of a `calloc` is resident before anything reads it.
 *
 * This is the probe behind the allocator-residency tables in docs/benchmarks/memory.md §7, the
 * measurement that turns "the receive batch is resident on an idle session" into "calloc memsets
 * small blocks". It allocates `count` blocks of `size` bytes with calloc, never touches them, and
 * reports how much of the allocated total became resident (RSS), as a percentage.
 *
 * 100% means the allocator memset every byte and faulted every page, which is exactly what a
 * per-slot `vec![0u8; MTU_LIMIT]` batch did. ~0% means the block came from a fresh anonymous
 * mapping that calloc knows is already zero and left alone, which is what Go's allocator does for
 * kcp-go's identical 256 x 1500 B batch and what the one-contiguous-allocation `RecvBatch` gets.
 *
 * With `generations` > 1 it repeats that, freeing every block between generations: the question
 * is whether a *replacement* block still gets the fresh mapping, which is allocator policy rather
 * than a property of the size. It matters because a real kcptun client frees a session's batch
 * when the session dies and callocs another one for its replacement. glibc in particular raises
 * its dynamic mmap threshold to the size of the first large mapped chunk it frees, after which an
 * identically sized calloc is served from the arena and memset.
 *
 * See tools/bench/callocprobe/README.md for how it is built and the invocations that produced the
 * tables. Nothing we ship depends on this file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Resident set size in bytes: /proc/self/statm field 2 (pages), Linux only. */
static long long rss_bytes(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    if (f == NULL) {
        return -1;
    }
    long long total = 0, resident = 0;
    int got = fscanf(f, "%lld %lld", &total, &resident);
    fclose(f);
    if (got != 2) {
        return -1;
    }
    return resident * (long long)sysconf(_SC_PAGESIZE);
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "usage: callocprobe <count> <size-bytes> [generations] [touch]\n");
        return 2;
    }
    unsigned long count = strtoul(argv[1], NULL, 10);
    unsigned long size = strtoul(argv[2], NULL, 10);
    unsigned long gens = argc >= 4 ? strtoul(argv[3], NULL, 10) : 1;
    int touch = argc == 5 && strcmp(argv[4], "touch") == 0;
    if (count == 0 || size == 0 || gens == 0) {
        fprintf(stderr, "callocprobe: count, size and generations must be non-zero\n");
        return 2;
    }
    if (argc == 5 && !touch) {
        fprintf(stderr, "callocprobe: the fourth argument, if given, must be `touch`\n");
        return 2;
    }

    /* Warm the allocator and the stdio buffers first, so the deltas below are only the blocks. */
    void *warm = calloc(1, 4096);
    if (warm == NULL) {
        perror("calloc");
        return 1;
    }
    memset(warm, 1, 4096);

    void **blocks = calloc(count, sizeof(void *));
    if (blocks == NULL) {
        perror("calloc");
        return 1;
    }
    memset(blocks, 0, count * sizeof(void *));

    long long allocated = (long long)count * (long long)size;
    for (unsigned long g = 1; g <= gens; g++) {
        long long before = rss_bytes();
        if (before < 0) {
            fprintf(stderr, "callocprobe: /proc/self/statm unavailable (Linux only)\n");
            return 1;
        }

        for (unsigned long i = 0; i < count; i++) {
            blocks[i] = calloc(1, size);
            if (blocks[i] == NULL) {
                perror("calloc");
                return 1;
            }
            /*
             * Not one byte of blocks[i] is read or written here, unless `touch` was asked for
             * (which models a session that carried traffic before it died): whatever RSS grows
             * by is otherwise the allocator's own doing.
             */
            if (touch && g < gens) {
                memset(blocks[i], (int)(i & 0xffUL), size);
            }
        }

        long long grew = rss_bytes() - before;
        if (grew < 0) {
            grew = 0;
        }
        printf("gen=%lu/%lu count=%lu size=%lu touched=%s allocated=%lld resident_delta=%lld "
               "percent=%.0f\n",
               g, gens, count, size, (touch && g < gens) ? "yes" : "no", allocated, grew,
               100.0 * (double)grew / (double)allocated);

        /* Free before the next generation; the last generation's blocks stay alive to the end. */
        if (g < gens) {
            for (unsigned long i = 0; i < count; i++) {
                free(blocks[i]);
                blocks[i] = NULL;
            }
        }
    }

    /* Keep the last generation alive past the samples above. */
    for (unsigned long i = 0; i < count; i++) {
        if (blocks[i] == NULL) {
            return 1;
        }
    }
    return 0;
}
