package sharerequests;

import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Timer;
import java.util.TimerTask;

/**
 * This class holds all our shared data used throughout the extension.
 */
public class SharedValues {

    //Burp callback and helper methods
    private final IBurpExtenderCallbacks callbacks;
    //Table model for storing the shared links of a user
    private final SharedLinksModel sharedLinksModel;
    //JSON library
    private final Gson gson;
    //AES Encryption key for the user
    private SecretKey secretKey;
    //AES IV for encryption
    private IvParameterSpec ivSpec;
    //Tiny local web server for catching shared link requests
    private CustomURLServer innerServer;
    //AWS Cognito client for performing API actions
    private final CognitoClient cognitoClient;
    //flag for determining whether to skip signon page when loading extension
    private boolean hasLoggedInBefore;
    //Timer for refreshing users session to the API
    private Timer timer;


    public SharedValues(IBurpExtenderCallbacks callbacks) throws IOException, NoSuchAlgorithmException {
        this.callbacks = callbacks;
        this.sharedLinksModel = new SharedLinksModel(callbacks);
        this.gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        //load our extension settings
        hasLoggedInBefore =
                callbacks.loadExtensionSetting("hasLoggedIn") != null;
        String rememberUserToken = callbacks.loadExtensionSetting("refresh");

        /*
            if the user asks to be remembered we skip the login page by using
            the refresh token to reload the session and init the user variables
         */
        if( rememberUserToken != null ) {
            this.cognitoClient = new CognitoClient(this, rememberUserToken);
            initUser(callbacks.loadExtensionSetting("username") );
        } else {
            this.cognitoClient = new CognitoClient(this);
        }
    }

    public IBurpExtenderCallbacks getCallbacks() {
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

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public IvParameterSpec getIvSpec() {
        return ivSpec;
    }

    /**
     * Toggles whether to remember the users session
     * @param rememberMe status of Remember Me checkbox 1 for yes 0 for no
     */
    public void setRememberMe(boolean rememberMe) {
        if(rememberMe) {
            getCallbacks().printOutput("Remembering user");
            //remember the user by storing the refresh token
            getCallbacks().saveExtensionSetting("refresh",
                    getCognitoClient().getRefreshToken());
        } else {
            getCallbacks().printOutput("Forgetting user");
            getCallbacks().saveExtensionSetting("refresh",
                    null);
        }
    }

    /**
     * This initializes the user to enable using the API.
     * If the user has never logged in before we generate an AES-128 key and
     * iv which is used to encrypt all messages shared.
     * If the user has logged in before we load the key and iv from extension
     * storage.
     * @param username used to XOR "decrypt" the stored key and iv information
     */
    public void initUser(String username) throws NoSuchAlgorithmException,
            IOException {
        callbacks.saveExtensionSetting("username",username);
        //check if user has logged in before (hasLoggedIn will be non null)
        if(hasLoggedInBefore == false) {
            /*
                first time login, make their encryption keys and store them
                XOR encrypted with their password. This isn't bullet proof
                but we need to store them somehow and if you're worried about
                someone on your machine stealing these you have bigger problems
             */
            generateKey();
            generateIv();
            callbacks.saveExtensionSetting("key",
                            Arrays.toString(Utils.XORencrypt(Base64.getEncoder().encodeToString(this.getSecretKey().getEncoded()),username)));
            callbacks.saveExtensionSetting("iv",
                Arrays.toString(Utils.XORencrypt(Base64.getEncoder().encodeToString(this.getIvSpec().getIV()),username)));
            callbacks.saveExtensionSetting("hasLoggedIn","1");
        } else {
            //we have logged in before so lets load our encryption keys
            String keyMaterial = callbacks.loadExtensionSetting("key");
            int[] decoded = Arrays.stream(keyMaterial.substring(1, keyMaterial.length()-1).split(
                    ","))
                    .map(String::trim).mapToInt(Integer::parseInt).toArray();
            String decrypted = Utils.XORdecrypt(decoded,username);
            byte[] decodedKey = Base64.getDecoder().decode(decrypted);
            this.secretKey = new SecretKeySpec(decodedKey, 0,
                    decodedKey.length,
                "AES");
            String ivMaterial = callbacks.loadExtensionSetting("iv");
            int[] decodedIv = Arrays.stream(ivMaterial.substring(1,
                    ivMaterial.length()-1).split(
                    ","))
                    .map(String::trim).mapToInt(Integer::parseInt).toArray();
            String decryptedIv = Utils.XORdecrypt(decodedIv,username);
            this.ivSpec = new IvParameterSpec(Base64.getDecoder().decode(decryptedIv));
        }

        populateRequestTable();

        timer = new Timer();
        timer.schedule( new TimerTask() {
            public void run() {
                getCognitoClient().refreshTokens();
            }
        }, 0, 2*60*(long)1000);

    }

    public Timer getTimer() {
        return timer;
    }

    public boolean hasLoggedInBefore() {
        return hasLoggedInBefore;
    }

    /**
     * Used by the "Forget Me" button to clear out the users session and flags
     */
    public void clearHasLoggedInBefore() {
        hasLoggedInBefore=false;
        getCallbacks().saveExtensionSetting("hasLoggedIn",null);
        getCallbacks().saveExtensionSetting("refresh", null);
        getCallbacks().saveExtensionSetting("username",null);

    }

    /**
     * "Rehydrates" the users shared requests by appending the key and iv to
     * the request url.
     */
    private void populateRequestTable() throws IOException {
        SharedRequest[] shareables = getCognitoClient().getMyMessages();
        for(SharedRequest s : shareables) {
            //rehydrate key & iv for sharable url since we don't have this
            // server side
            s.setShareableUrl(Utils.convertAwsMessageToCustomUrl(
                    s.getShareableUrl()
                    +"?key="+Base64.getEncoder().encodeToString(getSecretKey().getEncoded())
                    +"&iv="+Base64.getEncoder().encodeToString(getIvSpec().getIV()))
            );
            getSharedLinksModel().addBurpMessage(s);
        }
    }

    private void generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        this.secretKey = keyGenerator.generateKey();
        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        this.callbacks.printOutput(encodedKey);
    }

    private void generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        this.ivSpec= new IvParameterSpec(iv);
        String encodedIv = Base64.getEncoder().encodeToString(ivSpec.getIV());
        this.callbacks.printOutput(encodedIv);
    }

    public CognitoClient getCognitoClient() {
        return cognitoClient;
    }
}
