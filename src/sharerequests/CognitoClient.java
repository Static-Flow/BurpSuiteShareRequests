package sharerequests;

import burp.IHttpRequestResponse;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClientBuilder;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class CognitoClient {

    private String username;
    public static final String CLIENTID = "3es9k5el43odri9i5tdua489fq";
    private String idToken;
    private String refreshToken;
    private final SharedValues sharedValues;

    public CognitoClient(SharedValues sv){
        this.sharedValues = sv;
    }

    public CognitoClient(SharedValues sv, String refreshToken){
        this.sharedValues = sv;
        this.refreshToken = refreshToken;
        this.refreshTokens();

    }

    public CognitoIdentityProviderClient getCognitoClient() {
        CognitoIdentityProviderClientBuilder cognitoBuilder = CognitoIdentityProviderClient.builder();
        return cognitoBuilder.credentialsProvider(AnonymousCredentialsProvider.create()).region(Region.US_EAST_1).build();
    }

    public void refreshTokens() {
        HashMap<String, String> credentialMap = new HashMap<>();
        credentialMap.put("REFRESH_TOKEN", refreshToken);
        try {
            InitiateAuthResponse response =
                    getCognitoClient().initiateAuth(InitiateAuthRequest.builder()
                            .authFlow(AuthFlowType.REFRESH_TOKEN)
                            .clientId(CLIENTID)
                            .authParameters(Collections.unmodifiableMap(credentialMap)).build());
            idToken = response.authenticationResult().idToken();
            sharedValues.getCallbacks().printOutput("Refreshed token");
        } catch (Exception e) {
            sharedValues.getCallbacks().printError("Couldn't refresh token: " + e.getMessage());
        }
    }

    public boolean login(String username, String password,
                         boolean rememberUser) {
        HashMap<String, String> credentialMap = new HashMap<>();
        credentialMap.put("USERNAME", username);
        credentialMap.put("PASSWORD", password);
        try {
            InitiateAuthResponse response =
                    getCognitoClient().initiateAuth(InitiateAuthRequest.builder()
                            .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                            .clientId(CLIENTID)
                            .authParameters(Collections.unmodifiableMap(credentialMap)).build());
            idToken = response.authenticationResult().idToken();
            refreshToken = response.authenticationResult().refreshToken();
            if( rememberUser ) {
                sharedValues.setRememberMe(true);
            } else {
                sharedValues.setRememberMe(false);
            }
            return true;
        } catch (Exception e) {
            sharedValues.getCallbacks().printError(e.getMessage());
            return false;
        }
    }

    public boolean signup(String username, String password,
                                 String email) {
        AttributeType[] userAttributes =
                new AttributeType[]{
                        AttributeType.builder().name("email").value(email).build()
                };
        try {
            getCognitoClient().signUp(SignUpRequest.builder()
                    .clientId(CLIENTID)
                    .userAttributes(userAttributes)
                    .username(username)
                    .password(password).build());
            return true;
        } catch (Exception e) {
            sharedValues.getCallbacks().printOutput(e.getMessage());
            return false;
        }
    }

    public boolean verifyCode(String username, String code) {
        try {
            getCognitoClient().confirmSignUp(ConfirmSignUpRequest.builder()
                    .username(username)
                    .confirmationCode(code)
                    .clientId(CLIENTID)
                    .build());
            return true;
        } catch (Exception e) {
            sharedValues.getCallbacks().printOutput(e.getMessage());
            return false;
        }
    }

    public void logout() {
        sharedValues.getSharedLinksModel().clearTable();
        getCognitoClient().revokeToken(RevokeTokenRequest.builder().clientId(CLIENTID).token(refreshToken).build());
        idToken = null;
        refreshToken = null;
        sharedValues.getCallbacks().saveExtensionSetting("refresh",null);
        sharedValues.getCallbacks().saveExtensionSetting("username",null);
    }

    public SharedRequest[] getMyMessages() throws IOException {
        URL url = new URL("https://ywlwvcxl0k.execute-api.us-east-1.amazonaws.com/prod/me");
        HttpURLConnection con = makeConnection(url,
                "GET","application/json");
        String content = readOutput(con);
        return sharedValues.getGson().fromJson(content,SharedRequest[].class);
    }

    public SharedRequest sendMessage(HttpRequestResponse request) throws IOException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        URL url = new URL("https://ywlwvcxl0k.execute-api.us-east-1.amazonaws.com/prod/shareRequest");
        HttpURLConnection con = makeConnection(url,
                "POST","text/plain");
        SharedRequest sharable = new SharedRequest(
                request.convertBurpMessageToString(sharedValues.getSecretKey(),sharedValues.getIvSpec()),
                sharedValues.getCallbacks().getHelpers().analyzeRequest(request).getUrl().toString());
        String jsonData = sharedValues.getGson().toJson(sharable);
        byte[] body = jsonData.getBytes(StandardCharsets.UTF_8);
        String content = readOutput(postToConnection(con,body));
        sharable.setShareableUrl(Utils.convertAwsMessageToCustomUrl(
        "https://ywlwvcxl0k.execute-api.us-east-1.amazonaws" +
            ".com/prod/request/"+
            content+
            "?key="+
            Base64.getEncoder().encodeToString(sharedValues.getSecretKey().getEncoded()) +
            "&iv="+
            Base64.getEncoder().encodeToString(sharedValues.getIvSpec().getIV())));
        return sharable;
    }

    public IHttpRequestResponse getMessage(String url) throws IOException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        URL parsedUrl = new URL(url);
        sharedValues.getCallbacks().printOutput(parsedUrl.toString());
        HttpURLConnection con = makeConnection(new URL(url.split("\\?")[0]),
                "GET","text/plain");
        String content = readOutput(con);
        Map<String,String> keyAndIv = Utils.extractKeyAndIvFromUrl(parsedUrl);
        byte[] decodedKey = Base64.getDecoder().decode(keyAndIv.get("key"));
        IvParameterSpec iv =
                new IvParameterSpec(Base64.getDecoder().decode(keyAndIv.get(
                        "iv")));
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return Utils.messageToHttpRequest(content,
                originalKey,iv);

    }

    public boolean deleteMessage(URL key) throws IOException {
        sharedValues.getCallbacks().printOutput(key.toString());
        HttpURLConnection con = makeConnection(key,
                "DELETE","application/json");
        if(con.getResponseCode() == 200) {
            return true;
        } else {
            String content = readOutput(con);
            sharedValues.getCallbacks().printError(content);
            return false;
        }

    }

    private HttpURLConnection makeConnection(URL url,String method,
                                             String acceptHeader) throws IOException {
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        con.setRequestMethod(method);
        con.setRequestProperty("Accept", acceptHeader);
        con.setRequestProperty("Authorization",idToken);
        con.setDoOutput(true);
        return con;
    }

    private HttpURLConnection postToConnection(HttpURLConnection con,
                                               byte[] body) throws IOException {
        con.getOutputStream().write(body,0,body.length);
        return con;
    }


    private String readOutput(HttpURLConnection con) throws IOException {
        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuilder content = new StringBuilder();
        while ((inputLine = in.readLine()) != null) {
            content.append(inputLine);
        }
        in.close();
        con.disconnect();
        return content.toString();
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

}
