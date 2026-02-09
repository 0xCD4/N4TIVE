package com.ctf.nativectf.challenges;

public class Ch05 {
    static { System.loadLibrary("ch05_heapcraft"); }

    public native int allocate(int slotId, byte[] data);
    public native int release(int slotId);
    public native int edit(int slotId, byte[] data);
    public native byte[] read(int slotId);
    public native long getArenaBase();
    public native long getSlotSize();
    public native boolean verifyFlag(String input);
}
