package com.ctf.nativectf.challenges;

public class Ch02 {
    static { System.loadLibrary("ch02_stacksmasher"); }

    public native int processInput(byte[] input);
    public native long getHiddenOffset();
    public native boolean verifyFlag(String input);
}
