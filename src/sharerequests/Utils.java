package sharerequests;

import com.google.gson.Gson;
import software.amazon.awssdk.utils.IoUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * This class holds methods that don't fit in anywhere else or are used
 * multiple places
 */
public class Utils {

    private Utils(){}

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * This method converts an encrypted shared message from the API back
     * into a Request object that can be imported into Burp.
     * @param message encrypted and compressed request
     * @param key users AES key
     * @param iv users AES iv
     */
    public static HttpRequestResponse messageToHttpRequest(String message,
           SecretKey key,
           IvParameterSpec iv) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        byte[] messageBytes =
                Utils.decompress(Utils.decrypt(Utils.hexStringToByteArray(message),
                        key,
                        iv));
        Gson gson = new Gson();
        return gson.fromJson(new String(messageBytes, StandardCharsets.UTF_8),
                HttpRequestResponse.class);
    }

    public static byte[] decompress(final byte[] bytes) throws IOException {
        return IoUtils.toByteArray(new GZIPInputStream(new ByteArrayInputStream(bytes)));
    }

    public static byte[] compress(final byte[] bytes) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(bytes.length);
        GZIPOutputStream gzip = new GZIPOutputStream(bos);
        gzip.write(bytes);
        gzip.close();
        return bos.toByteArray();
    }

    public static String convertAwsMessageToCustomUrl(String awsMessageUrl) {
        return "http://burpsharedrequest/"+ Base64.getEncoder().encodeToString(awsMessageUrl.getBytes());
    }


    public static byte[] encrypt(byte[] input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchAlgorithmException
            , InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(input);
    }

    public static byte[] decrypt(byte[] cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(cipherText);
    }

    public static Map<String, String> extractKeyAndIvFromUrl(URL url) throws UnsupportedEncodingException {
        Map<String, String> queryPairs = new HashMap<>();
        String query = url.getQuery();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            queryPairs.put(pair.substring(0, idx), pair.substring(idx + 1));
        }
        return queryPairs;
    }

    public static int[] XORencrypt(String str, String key) {
        int[] output = new int[str.length()];
        for(int i = 0; i < str.length(); i++) {
            int o = ((int) str.charAt(i) ^ (int) key.charAt(i % (key.length() - 1))) + '0';
            output[i] = o;
        }
        return output;
    }

    public static String XORdecrypt(int[] input, String key) {
        StringBuilder output = new StringBuilder();
        for(int i = 0; i < input.length; i++) {
            output.append((char) ((input[i] - 48) ^ (int) key.charAt(i % (key.length() - 1))));
        }
        return output.toString();
    }
}
