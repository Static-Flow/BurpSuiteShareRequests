package burp;

import sharerequests.*;

import java.awt.*;
import java.io.IOException;

public class BurpExtender
        implements IBurpExtender, ITab {
    private SharedValues sharedValues;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        iBurpExtenderCallbacks.setExtensionName("Burp Shared Requests");
        this.sharedValues = new SharedValues(iBurpExtenderCallbacks);
        iBurpExtenderCallbacks.addSuiteTab(this);
        iBurpExtenderCallbacks.registerContextMenuFactory(new ManualRequestSenderContextMenu(this.sharedValues));
        iBurpExtenderCallbacks.registerProxyListener(new ProxyListener(this.sharedValues));
        iBurpExtenderCallbacks.registerExtensionStateListener(new ExtensionStateListener(this.sharedValues));
        CustomURLServer innerServer;
        try {
            innerServer = new CustomURLServer(sharedValues);
            Thread innerServerThread = new Thread(innerServer);
            innerServerThread.start();
            sharedValues.setInnerServer(innerServer);
        } catch (IOException e) {
            iBurpExtenderCallbacks.printError(e.getMessage());
        }
    }

    public String getTabCaption() {
        return "Burp Share Requests";
    }

    public Component getUiComponent() {
        return new ExtensionPanel(this.sharedValues);
    }
}
