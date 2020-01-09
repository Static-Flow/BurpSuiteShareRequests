package sharerequests;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;

public class SharedValues {

    private IBurpExtenderCallbacks callbacks;
    private SharedLinksModel sharedLinksModel;
    private Gson gson;
    private CustomURLServer innerServer;

    public SharedValues(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.sharedLinksModel = new SharedLinksModel(callbacks);
        this.gson = new Gson();
    }

    IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    SharedLinksModel getSharedLinksModel() {
        return sharedLinksModel;
    }

    Gson getGson() {
        return gson;
    }

    public void setInnerServer(CustomURLServer innerServer) {
        this.innerServer = innerServer;
    }

    CustomURLServer getInnerServer() {
        return innerServer;
    }
}
