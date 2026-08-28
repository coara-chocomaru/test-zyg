package android.os;

import android.os.WorkSource;
import android.os.PowerSaveState;

interface IPowerManager {
    void acquireWakeLock(IBinder lock, int flags, String tag, String packageName, WorkSource ws, String historyTag);
    void acquireWakeLockWithUid(IBinder lock, int flags, String tag, String packageName, int uidtoblame);
    void boostScreenBrightness(long time);
    void crash(String message);
    int getLastShutdownReason();
    PowerSaveState getPowerSaveState(int serviceType);
    void goToSleep(long time, int reason, int flags);
    boolean isDeviceIdleMode();
    boolean isInteractive();
    boolean isLightDeviceIdleMode();
    boolean isPowerSaveMode();
    boolean isScreenBrightnessBoosted();
    boolean isWakeLockLevelSupported(int level);
    void nap(long time);
    void powerHint(int hintId, int data);
    void reboot(boolean confirm, String reason, boolean wait);
    void rebootSafeMode(boolean confirm, boolean wait);
    void releaseWakeLock(IBinder lock, int flags);
    void setAttentionLight(boolean on, int color);
    void setDozeAfterScreenOff(boolean on);
    boolean setPowerSaveMode(boolean mode);
    void setStayOnSetting(int val);
    void shutdown(boolean confirm, String reason, boolean wait);
    void updateWakeLockUids(IBinder lock, int[] uids);
    void updateWakeLockWorkSource(IBinder lock, WorkSource ws, String historyTag);
    void userActivity(long time, int event, int flags);
    void wakeUp(long time, String reason, String opPackageName);
}
