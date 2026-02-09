package com.ctf.nativectf.challenges;

public class Ch03 {
    static { System.loadLibrary("ch03_typeconfusion"); }

    /** Helper class for gate3 TOCTOU attack */
    public static class Validator {
        public volatile int token;
        public Validator(int token) { this.token = token; }
    }

    public native int gate1(Object input);
    public native int gate2(Object input);
    public native int gate3(Validator validator);
    public native int gate4(byte[] payload);
    public native String combine();
    public native boolean verifyFlag(String input);
}
