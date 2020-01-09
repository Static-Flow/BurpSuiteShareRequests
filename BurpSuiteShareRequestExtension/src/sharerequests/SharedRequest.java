package sharerequests;

public class SharedRequest {
    private HttpRequestResponse requestResponse;
    private String datetime;

    SharedRequest(HttpRequestResponse burpMessage, String datetime) {
        this.requestResponse = burpMessage;
        this.datetime = datetime;
    }

    HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public String getDatetime() {
        return datetime;
    }

}
