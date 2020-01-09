package sharerequests;

import burp.IExtensionStateListener;

public class ExtensionStateListener
        implements IExtensionStateListener {
    private final SharedValues sharedValues;

    public ExtensionStateListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    public void extensionUnloaded() {
        this.sharedValues.getInnerServer().stopRunning();
    }
}
