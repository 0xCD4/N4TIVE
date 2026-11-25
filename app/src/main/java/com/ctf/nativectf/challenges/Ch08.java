package com.ctf.nativectf.challenges;

public class Ch08 {
    static { System.loadLibrary("ch08_signalmaze"); }

    public native String walk(String code);
    public native boolean verifyFlag(String input);
}
