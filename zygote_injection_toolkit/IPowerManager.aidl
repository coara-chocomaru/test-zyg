package android.os;

interface IPowerManager {
    void reboot(boolean confirm, String reason, boolean wait);
}
