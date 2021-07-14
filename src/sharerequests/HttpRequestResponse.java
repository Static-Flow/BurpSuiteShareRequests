package sharerequests;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import com.google.gson.Gson;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HttpRequestResponse implements IHttpRequestResponse {

    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private IHttpService httpService;

    HttpRequestResponse() {
    }

    @Override
    public byte[] getRequest() {
        if(request == null) {
            return new byte[]{};
        }
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        request = message;
    }

    @Override
    public byte[] getResponse() {

        if(response == null) {
            return new byte[]{};
        }
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        response = message;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String color) {
        this.highlight = color;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }

    /**
     * This method performs a nested set of steps to prepare a request for
     * transmission to the API: request -> json -> gzip -> AES -> hex
     * request : the bytes of this request
     * json : json encode the request bytes
     * gzip : gzip compress json
     * AES : AES-128 encrypt the gzip blob
     * hex : convert AES bytes to hex for easier transmission
     * @param key user's AES encryption key
     * @param iv user's IV value needed used for AES encryption
     * @return converted Burp request
     */
    public String convertBurpMessageToString(SecretKey key,
                                             IvParameterSpec iv) throws IOException,
            NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        return Utils.bytesToHex(Utils.encrypt(Utils.compress(burpMessageToJson()),key,iv));
    }

    private byte[] burpMessageToJson() {
        Gson gson = new Gson();
        return gson.toJson(this).getBytes();
    }

    @Override
    public String toString() {
        return "HttpRequestResponse{" +
                "request=" + Arrays.toString(request) +
                ", response=" + Arrays.toString(response) +
                ", comment='" + comment + '\'' +
                ", highlight='" + highlight + '\'' +
                ", httpService=" + httpService;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HttpRequestResponse that = (HttpRequestResponse) o;
        return Arrays.equals(request, that.request) &&
                Arrays.equals(response, that.response);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(request);
        result = 31 * result + Arrays.hashCode(response);
        return result;
    }
}
