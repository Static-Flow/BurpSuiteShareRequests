package burp;

import sharerequests.*;

import java.awt.*;

public class BurpExtender
        implements IBurpExtender, ITab {
    private SharedValues sharedValues;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        iBurpExtenderCallbacks.setExtensionName("Burp Shared Requests");
        try {
            this.sharedValues = new SharedValues(iBurpExtenderCallbacks);
            iBurpExtenderCallbacks.addSuiteTab(this);
            iBurpExtenderCallbacks.registerContextMenuFactory(new ManualRequestSenderContextMenu(this.sharedValues));
            iBurpExtenderCallbacks.registerProxyListener(new ProxyListener(this.sharedValues));
            iBurpExtenderCallbacks.registerExtensionStateListener(new ExtensionStateListener(this.sharedValues));
            CustomURLServer innerServer;
            innerServer = new CustomURLServer(sharedValues);
            Thread innerServerThread = new Thread(innerServer);
            innerServerThread.start();
            sharedValues.setInnerServer(innerServer);
        } catch (Exception e) {
            iBurpExtenderCallbacks.printError(e.getMessage());
        }
    }

    public String getTabCaption() {
        return "Burp Share Requests";
    }

    public Component getUiComponent() {
        return new GuiPanel(this.sharedValues);
    }
}
