package sharerequests;

import burp.IExtensionStateListener;

import java.util.Timer;

/**
 * Handles unloading the extension to stop our custom web server and session
 * refresher threads
 */
public class ExtensionStateListener
        implements IExtensionStateListener {
    private final SharedValues sharedValues;

    public ExtensionStateListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    public void extensionUnloaded() {
        this.sharedValues.getInnerServer().stopRunning();
        Timer timer = this.sharedValues.getTimer();
        if (timer != null) {
            timer.cancel();
        }
    }
}
