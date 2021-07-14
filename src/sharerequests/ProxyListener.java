package sharerequests;

import burp.*;

import javax.swing.*;
import java.util.Base64;

public class ProxyListener implements IProxyListener {

    private final SharedValues sharedValues;

    public ProxyListener(SharedValues sharedValues) {
        this.sharedValues = sharedValues;
    }

    /**
     * This watches every request come through the proxy and filters for the
     * custom protocol. If found, this extension extracts the base64 contents
     * of the url and processes it to retrieve the encrypted request, decrypt
     * it and create a new Repeater tab containing the request.
     */
    public void processProxyMessage(boolean isResponse,
                                    IInterceptedProxyMessage iInterceptedProxyMessage) {
        IHttpService httpService = iInterceptedProxyMessage.getMessageInfo().getHttpService();
        if ("burpsharedrequest".equalsIgnoreCase(iInterceptedProxyMessage.getMessageInfo().getHttpService().getHost())) {
            sharedValues.getCallbacks().printOutput("got custom link request");
            sharedValues.getCallbacks().issueAlert("This host processed a " +
                    "shared request link. If you did not paste this " +
                    "yourself or click on a link you should leave that site.");
            IRequestInfo requestInfo =
                    sharedValues.getCallbacks().getHelpers().analyzeRequest(iInterceptedProxyMessage.getMessageInfo());
            String requestAWSUrl =
                    new String(Base64.getDecoder().decode(requestInfo.getUrl().getPath().substring(1)));
            if(requestAWSUrl.startsWith("https://ywlwvcxl0k.execute-api" +
                    ".us-east-1.amazonaws.com/prod/request/")) {
                sharedValues.getCallbacks().printOutput(requestAWSUrl);
                try {

                    IHttpRequestResponse parsedRequest =
                            sharedValues.getCognitoClient().getMessage(requestAWSUrl);
                    new SwingWorker<Boolean, Void>() {
                        @Override
                        public Boolean doInBackground() {
                            sharedValues.getCallbacks().sendToRepeater(
                                    parsedRequest.getHttpService().getHost(),
                                    parsedRequest.getHttpService().getPort(),
                                    parsedRequest.getHttpService().getProtocol().equalsIgnoreCase("https"),
                                    parsedRequest.getRequest(),
                                    "Burp Shared Link Payload");
                            return true;
                        }

                        @Override
                        public void done() {
                            //we don't need to do any cleanup so this is empty
                        }
                    }.execute();
                } catch (Exception e) {
                    sharedValues.getCallbacks().printError(e.getMessage());
                    sharedValues.getCallbacks().issueAlert("This host " +
                            "attempted to access an invalid shared request.");
                }
            } else {
                sharedValues.getCallbacks().printError("Bad url");
                sharedValues.getCallbacks().issueAlert("This host processed a" +
                        " shared request link that attempted to send you to a" +
                        " nonstandard API. Be wary of the source of the link.");
            }
            iInterceptedProxyMessage.getMessageInfo().setHttpService(this.sharedValues.getCallbacks().getHelpers().buildHttpService(
                    "127.0.0.1", this.sharedValues.getInnerServer().getSocket().getLocalPort(), httpService.getProtocol()));
        }
    }

}
