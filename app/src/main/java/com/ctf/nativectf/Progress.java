package com.ctf.nativectf;

import android.content.Context;
import android.content.SharedPreferences;

/** Remembers which challenges were solved. It stores a yes or no per challenge, never a flag. */
final class Progress {
    private static final String FILE = "progress";

    static boolean isSolved(Context context, String id) {
        return prefs(context).getBoolean(id, false);
    }

    static void markSolved(Context context, String id) {
        prefs(context).edit().putBoolean(id, true).apply();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    private Progress() { }
}
