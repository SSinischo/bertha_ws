import io.javalin.Context;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

public class Client {
    public static Map<String, Client> clients = new HashMap<>();
    public IvParameterSpec initializationVectors;
    public String authSession;

    String clientKey;
    RSAPublicKey rsaKey;
    SecretKey aesKey;

    Cipher rsaEncrypter;
    Cipher aesEncrypter;
    Cipher aesDecrypter;

    String authenticatedAsUser;
    boolean forceNewPassword;

    public static Client find(Context ctx){
        return clients.get(ctx.formParam("clientKey"));
    }

    public Client(){
        forceNewPassword = false;
        try {
            clientKey = assignClientKey();
            rsaEncrypter = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            aesEncrypter = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesDecrypter = Cipher.getInstance("AES/CBC/PKCS5Padding");

            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            aesKey = keygen.generateKey();

            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            byte[] ivParams = new byte[aesEncrypter.getBlockSize()];
            sr.nextBytes(ivParams);
            initializationVectors = new IvParameterSpec(ivParams);

            aesEncrypter.init(Cipher.ENCRYPT_MODE, aesKey, initializationVectors);
            aesDecrypter.init(Cipher.DECRYPT_MODE, aesKey, initializationVectors);
            clients.put(clientKey, this);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public String assignClientKey(){
        SecureRandom sr = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        while(sb.length() < 64)
            sb.append(Integer.toHexString(sr.nextInt()));
        return sb.toString().substring(0, 64);
    }
}