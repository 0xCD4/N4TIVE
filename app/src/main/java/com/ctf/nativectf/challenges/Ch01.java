package com.ctf.nativectf.challenges;

public class Ch01 {
    static { System.loadLibrary("ch01_stringmaze"); }

    public native String solve();
    public native boolean verifyFlag(String input);
}
