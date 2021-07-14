package sharerequests;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Base64;

/**
 * This class represents the model for a Shared Request.
 */
class SharedRequest {

    //requestData contains the gzip compressed, AES encrypted request bytes
    @SerializedName(value = "request")
    @Expose private final String requestData;
    //shareableUrl contains the URL given by the API to reference this request
    @SerializedName(value = "key")
    @Expose(serialize = false) private String shareableUrl;
    //description contains the URL of the request that was shared
    @SerializedName(value = "description")
    @Expose private final String description;

    SharedRequest(String requestData, String description) {
        this.requestData = requestData;
        this.description = description;
        this.shareableUrl = "";
    }

    void setShareableUrl(String url) {
        shareableUrl = url;
    }

    /**
     * This converts the custom shared url format back into the AWS API
     * format for use by the Cognito client
     */
    URL getShareableAWSUrl() throws MalformedURLException {
        //http://burpsharedrequest/(base64 data) ---v
        //https://api.amazonaws.com/prod/request/(user)/(object)?key&iv
        return new URL(new String(Base64.getDecoder().decode(getShareableUrl().split("burpsharedrequest/")[1])).split("\\?")[0]);
    }

    String getShareableUrl() {
        return shareableUrl;
    }

    String getDescription() {
        return description;
    }

}
