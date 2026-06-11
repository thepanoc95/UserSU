package android.app;

import android.content.ComponentName;

interface IServiceConnection {
    void connected(in ComponentName name, IBinder service, boolean dead);
}
