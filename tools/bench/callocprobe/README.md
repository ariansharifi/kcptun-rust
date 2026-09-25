# callocprobe (plan 12.3c)

`calloc` does not always memset. This 120-line C probe measures when it does, and it is the
evidence behind the allocator-residency tables in `docs/benchmarks/memory.md` §7 — the measurement
that turned *"the receive batch is resident on a session that has never received a datagram"* into
*"`calloc` memsets small blocks, and Go's allocator does not"*.

It allocates `count` blocks of `size` bytes, never reads or writes them, and prints how much of the
allocated total became resident (`/proc/self/statm`, so **Linux only**). With `generations > 1` it
frees every block and allocates them again, which is the session-churn case: glibc raises its
dynamic `mmap` threshold to the size of the first large mapped chunk it frees, so a *replacement*
batch need not be treated like the first one.

**Nothing we ship depends on this file.** It is C rather than Rust on purpose: the question is what
the *system allocator* does with a `calloc`, with no Rust runtime between the call and the answer.

## Build

lab-arm64 and lab-x86-1 have no C toolchain (tools/lab/README.md), so it is cross-compiled on the laptop
with the `zig` that `cargo-zigbuild` already needs:

```sh
zig cc -target aarch64-linux-gnu.2.39 -O2 -Wall -Wextra -o callocprobe-glibc  callocprobe.c
zig cc -target aarch64-linux-musl -O2 -static -Wall -Wextra -o callocprobe-musl callocprobe.c
zig cc -target x86_64-linux-gnu.2.35 -O2 -Wall -Wextra -o callocprobe-glibc-x86 callocprobe.c
```

Then `scp` them to `~/kcptun-lab/tests/bench/` and `rm -rf ~/kcptun-lab/tests/bench` afterwards, as
tools/lab/README.md requires. The probe opens no socket and runs in milliseconds.

## The invocations behind §7

All three shapes allocate the same 6 144 000 bytes — 16 whole `BATCH_SIZE` batches — so only the
block size differs:

```sh
./callocprobe-glibc 16 384000     # one contiguous batch per session, as RecvBatch allocates now
./callocprobe-glibc 4096 1500     # one vec![0u8; MTU_LIMIT] per slot, as it did before 12.3c
./callocprobe-glibc 1 6144000     # a single large block, for the threshold
```

and the churn table:

```sh
./callocprobe-glibc 16 384000 3          # three generations, each freed before the next
./callocprobe-glibc 16 384000 3 touch    # ... with every generation but the last written to first
```
