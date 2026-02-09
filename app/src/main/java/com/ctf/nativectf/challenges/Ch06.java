package com.ctf.nativectf.challenges;

public class Ch06 {
    static { System.loadLibrary("ch06_vm"); }

    public native byte[] execute(byte[] input);
    public native byte[] getBytecode();
    public native int getEncodingHint();
    public native boolean verifyFlag(String input);
}
