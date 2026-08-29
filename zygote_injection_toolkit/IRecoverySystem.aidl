package android.os;

import android.os.IRecoverySystemProgressListener;

interface IRecoverySystem {
    boolean uncrypt(String packageFile, IRecoverySystemProgressListener listener);
    boolean setupBcb(String command);
    boolean clearBcb();
    void rebootRecoveryWithCommand(String command);
}
