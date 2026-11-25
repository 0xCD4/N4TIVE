# N4TIVE

Android Native Reverse Engineering CTF

## Overview

N4TIVE is an eight-challenge Capture The Flag application focused on Android native library analysis. All challenges require reversing `.so` files compiled from C.

## Requirements

- Android device or emulator (API 26+)
- Ghidra, IDA Pro, or similar disassembler
- Frida (recommended for dynamic analysis)
- Basic understanding of ARM assembly and JNI

## Installation

```
adb install n4tive.apk
```

Build from source:

```
git clone https://github.com/0xCD4/N4TIVE.git
cd N4TIVE
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Challenges

### Challenge 01: String Maze
**Difficulty:** 1/5  
**Library:** libch01_stringmaze.so  
**Technique:** Static analysis, XOR decryption

The target string is encrypted with three layers of obfuscation. Trace the decryption chain in .rodata.

### Challenge 02: Stack Smasher
**Difficulty:** 2/5  
**Library:** libch02_stacksmasher.so  
**Technique:** Buffer overflow, control flow hijacking

A 64-byte stack buffer with no bounds checking. Overflow it to redirect execution to a hidden function.

### Challenge 03: Type Confusion
**Difficulty:** 3/5  
**Library:** libch03_typeconfusion.so  
**Technique:** JNI type mismatch exploitation

Four gates protect the target. Each gate expects a specific Java type but can be bypassed by passing incorrect types, triggering alternate code paths.

### Challenge 04: Anti-Debug Gauntlet
**Difficulty:** 3/5  
**Library:** libch04_gauntlet.so  
**Technique:** Anti-analysis bypass

Seven anti-debugging checks must pass or be bypassed:
1. TracerPid detection
2. Frida port/maps scanning
3. ptrace self-attach
4. Timing analysis
5. Software breakpoint detection
6. Java debugger check
7. APK signature verification

### Challenge 05: Heap Feng Shui
**Difficulty:** 4/5  
**Library:** libch05_heapcraft.so  
**Technique:** Heap exploitation, Use-After-Free

A custom slab allocator with 8 slots. An off-by-16 overflow allows corruption of adjacent slot metadata. Combined with a UAF vulnerability, hijack a function pointer.

### Challenge 06: Virtual Machine
**Difficulty:** 5/5  
**Library:** libch06_vm.so  
**Technique:** Custom VM reversing, constraint solving

A custom stack-based virtual machine with 32 opcodes. The bytecode is XOR-encoded. Reverse the instruction set, decode the bytecode, and solve the constraint system.

### Challenge 07: Ghost Export
**Difficulty:** 3/5  
**Library:** libch07_ghostexport.so  
**Technique:** Decoy export, RegisterNatives, ELF notes

The library exports a function with the JNI name of `reveal()`. That export is a decoy and answers with a flag the verifier rejects. The function Java reaches is bound in `JNI_OnLoad` through `RegisterNatives`. A constructor in `.init_array` runs first, finds a custom ELF note in the library's own program headers and takes a key from it. Find the hidden function, read the key with `readelf -n`, and invert the passphrase check.

### Challenge 08: Signal Maze
**Difficulty:** 4/5  
**Library:** libch08_signalmaze.so  
**Technique:** Control flow hidden in signal handlers

`walk()` takes a 16-character code and raises `SIGTRAP` once per character. The work happens in three signal handlers. Each one mixes the current byte into a 64-bit state, compares part of it with a checkpoint and installs the handler for the next step, so the order of the handlers depends on the code. Find the handlers through `sigaction`, rebuild the walk offline and recover the code one character at a time. A debugger that swallows the signal ends the walk.

## Flags

Every flag has the form `FLAG{...}` with a lowercase hexadecimal body. Submit it in the app, or check it offline.

```
./scripts/verify_flag.sh ch01 "FLAG{...}"
```

The script needs bash 4 or later and openssl. It holds the same salts and HMAC-SHA256 digests as `flag_core.c`, so it accepts exactly the flags the app accepts.

Challenge 06 derives its flag from the correct 16-byte input, so that flag is not stored in the library. Challenges 07 and 08 decrypt their flag with a key derived from the right passphrase or code.

## Maintaining the Flags

One script writes the encrypted tables in the challenge sources and the digests in `flag_core.c` and `scripts/verify_flag.sh`. It reads the flags from one secret file, so a table and its digest cannot drift apart.

```
python scripts/gen_flags.py new      # create FLAGS_SECRET.txt with random flags
python scripts/gen_flags.py extend   # add entries for new challenges, keep the others
python scripts/gen_flags.py apply    # rewrite the generated blocks
python scripts/gen_flags.py check    # fail if the sources and the secrets differ
```

`FLAGS_SECRET.txt` is ignored by git and has to stay private. The blocks between the `gen_flags begin` and `gen_flags end` markers are not edited by hand.

## Build Requirements

- Android Studio
- NDK (via SDK Manager)
- CMake 3.22.1+ (via SDK Manager)

## Project Structure

```
app/src/main/
├── assets/fonts/
│   ├── newsreader.ttf
│   └── schibsted_grotesk.ttf
├── java/com/ctf/nativectf/
│   ├── MainActivity.java
│   ├── ChallengeActivity.java
│   ├── Challenges.java
│   ├── Progress.java
│   ├── Ui.java
│   └── challenges/
│       └── Ch01.java - Ch08.java
└── jni/
    ├── CMakeLists.txt
    ├── flag_core.c
    ├── ch01_stringmaze.c
    ├── ch02_stacksmasher.c
    ├── ch03_typeconfusion.c
    ├── ch04_gauntlet.c
    ├── ch05_heapcraft.c
    ├── ch06_vm.c
    ├── ch07_ghostexport.c
    └── ch08_signalmaze.c

licenses/
├── OFL-Newsreader.txt
└── OFL-SchibstedGrotesk.txt

scripts/
├── gen_flags.py
└── verify_flag.sh
```

## Typefaces

The app sets its headings in Newsreader and its text in Schibsted Grotesk. Both are bundled as Latin subsets and are licensed under the SIL Open Font License 1.1. The licence texts are in `licenses/`.

## Author

Ahmet Goker
