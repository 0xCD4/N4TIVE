package com.ctf.nativectf;

/** What the two screens show about each challenge. */
final class Challenges {

    static final class Item {
        final String id;
        final String title;
        final String library;
        final int level;
        final String technique;
        final String summary;
        final String contact;
        final String approach;

        Item(String id, String title, String library, int level, String technique,
             String summary, String contact, String approach) {
            this.id = id;
            this.title = title;
            this.library = library;
            this.level = level;
            this.technique = technique;
            this.summary = summary;
            this.contact = contact;
            this.approach = approach;
        }

        String number() {
            return id.substring(2);
        }
    }

    static final int MAX_LEVEL = 5;

    static final Item[] ALL = {
        new Item("ch01", "String Maze", "libch01_stringmaze.so", 1,
            "Static analysis, layered XOR",
            "The flag is stored encrypted under three layers inside the library. "
                + "Reverse the decryption chain to recover it.",
            "solve() returns the first characters as a hint.",
            "Ghidra or IDA. Trace the XOR and permutation layers through .rodata."),

        new Item("ch02", "Stack Smasher", "libch02_stacksmasher.so", 2,
            "Buffer overflow, control-flow hijack",
            "processInput() copies its argument into a 64-byte stack buffer without "
                + "a length check. A function pointer sits directly behind the buffer.",
            "processInput(byte[]) and getHiddenOffset().",
            "Overwrite the pointer so the call lands in the hidden compute_secret(). "
                + "The seed it writes to logcat is the body of the flag."),

        new Item("ch03", "Type Confusion", "libch03_typeconfusion.so", 3,
            "JNI type mismatch, four gates",
            "Four gates guard four key fragments. Each gate takes a loosely typed "
                + "Java argument and leaks its fragment when it is handed the wrong "
                + "kind of object.",
            "gate1() to gate4() with crafted objects, then combine().",
            "Frida, to call native methods with arguments the Java signature "
                + "would not suggest."),

        new Item("ch04", "Anti-Debug Gauntlet", "libch04_gauntlet.so", 3,
            "Seven anti-analysis checks",
            "Seven anti-analysis checks stand in front of the flag. Each one "
                + "contributes a key byte, so all seven have to pass or be bypassed.",
            "getFlag(Context) and checkStatus(Context).",
            "Hook the checks with Frida and force the expected return values, "
                + "or patch the library."),

        new Item("ch05", "Heap Feng Shui", "libch05_heapcraft.so", 4,
            "Heap overflow, function pointer",
            "A slab allocator with eight slots. edit() writes sixteen bytes past "
                + "the data field, far enough to reach the read handler of the slot.",
            "allocate(), release(), edit(), read(), getArenaBase() and getSlotSize().",
            "Redirect the read handler to the hidden flag_generator()."),

        new Item("ch06", "Virtual Machine", "libch06_vm.so", 5,
            "Custom bytecode, constraint solving",
            "A stack-based virtual machine with 32 instructions runs a bytecode "
                + "program that is XOR-encoded in the binary. The program takes 16 "
                + "bytes, transforms them and compares the result with constants.",
            "execute(byte[]), getBytecode() and getEncodingHint().",
            "Recover the instruction set, decode and disassemble the program, "
                + "then solve the constraints. Z3 helps."),

        new Item("ch07", "Ghost Export", "libch07_ghostexport.so", 3,
            "Decoy export, RegisterNatives, ELF note",
            "The library exports a function with the JNI name of reveal(). It is "
                + "a decoy. The function Java reaches is bound at load time, and its "
                + "key sits in an ELF note that no code points to.",
            "reveal(String passphrase).",
            "Follow .init_array and JNI_OnLoad, or hook RegisterNatives. "
                + "Then invert the passphrase check."),

        new Item("ch08", "Signal Maze", "libch08_signalmaze.so", 4,
            "Logic inside signal handlers",
            "walk() raises a signal for every character of a 16-character code. "
                + "The work happens in three signal handlers, and each step decides "
                + "which handler comes next.",
            "walk(String code).",
            "Find the handlers through sigaction, rebuild the walk offline and "
                + "recover the code one character at a time."),
    };

    private Challenges() { }
}
