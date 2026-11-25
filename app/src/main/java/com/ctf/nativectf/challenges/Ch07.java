package com.ctf.nativectf.challenges;

public class Ch07 {
    static { System.loadLibrary("ch07_ghostexport"); }

    public native String reveal(String passphrase);
    public native boolean verifyFlag(String input);
}
