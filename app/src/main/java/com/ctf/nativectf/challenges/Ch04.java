package com.ctf.nativectf.challenges;

import android.content.Context;

public class Ch04 {
    static { System.loadLibrary("ch04_gauntlet"); }

    public native String getFlag(Context context);
    public native int checkStatus(Context context);
    public native boolean verifyFlag(String input);
}
