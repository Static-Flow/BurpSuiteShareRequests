package sharerequests;

import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

public class ProxyListener implements IProxyListener {

    private SharedValues sharedValues;

    public ProxyListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    public void processProxyMessage(boolean isResponse,
                                    IInterceptedProxyMessage iInterceptedProxyMessage) {
        IHttpService httpService = iInterceptedProxyMessage.getMessageInfo().getHttpService();
        if ("burpsharedrequest".equalsIgnoreCase(iInterceptedProxyMessage.getMessageInfo().getHttpService().getHost())) {
            System.out.println("got custom link request");
            sharedValues.getCallbacks().issueAlert("This host created a custom repeater payload. If you did not paste this yourself " +
                    "or clicked on a link you should leave that site.");
            iInterceptedProxyMessage.getMessageInfo().setHttpService(this.sharedValues.getCallbacks().getHelpers().buildHttpService(
                    "127.0.0.1", this.sharedValues.getInnerServer().getSocket().getLocalPort(), httpService.getProtocol()));
        }
    }

}
