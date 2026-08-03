# Autonomous development contract

RustOS is intended to advance through autonomous daily development runs. The configured GPT developer may choose and implement the next slice, but the repository does not launch a model by itself. A scheduler, CI runner, or local operator must invoke each run.

## Daily run

Each run should:

1. Read `ROADMAP.md`, the current `main` state, recent verification evidence, and the target-machine hardware notes.
2. Select the highest-value unfinished blocker to replacing CachyOS as a daily desktop OS. Prefer a complete vertical slice over cosmetic expansion.
3. Make the smallest coherent Rust implementation that moves that blocker.
4. Run formatting, host tests, `cargo run -p rustos-xtask -- check`, and the narrowest relevant BIOS/UEFI proof. Add or update tests before claiming the slice.
5. Preserve unrelated dirty work, commit only the intended change directly on `main`, push `origin/main`, and record the exact local/remote SHA.
6. Leave a short evidence-based handoff: what works, what was tested, what remains hardware-gated, and the next best slice.

## Acceptance floors

QEMU is a regression harness, not proof that the Ryzen 7 5800X/RTX 5070 machine works. Native claims require a real boot and runtime check on that machine. In particular, the NVIDIA graphics stack, Intel I225-V networking, motherboard audio, USB topology, storage controllers, suspend/resume, power management, and installer writes remain separate hardware gates.

The autonomous loop must not repartition disks, flash firmware, alter host boot configuration, or make other destructive hardware changes without an explicit user-directed run. It must not convert a source test, a QEMU result, a feature branch, or an unpushed commit into a delivery claim.

## What “every day” means

When a scheduler invokes the developer, the expected unit is one verified slice per invocation. If no scheduler invokes it, no background development is happening; this chat session does not continue running after it ends. The model name can change, but the evidence and safety contract does not.

The daily target is not an ever-growing demo. It is a monotonically more usable Rust-owned system: boot, storage, input, networking, graphics, audio, power, accounts, packaging, installation, and recovery must each move from emulated proof to native hardware proof before RustOS can replace CachyOS.
