import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;
import com.google.gson.JsonObject;
import io.javalin.Context;
import io.javalin.UnauthorizedResponse;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class Authentication {
    final static String awsClientId = "6pnbv0ne1hdvmfgs6q2jkkeskf";
    final static String awsUserPool = "us-east-1_1abyUmkI0";

    AWSCredentialsProvider acp;
    AWSCognitoIdentityProvider idp;

    public Authentication(){
        AWSCredentials creds = new AWSCredentials() {
            @Override
            public String getAWSAccessKeyId() {
                return "AKIAJFKGVAWXPRQ6BCVA";
            }

            @Override
            public String getAWSSecretKey() {
                return "ADds+6Wzj6ehsZYHmH4EWkSrj+givzEusoJnL7f5";
            }
        };
        acp = new AWSStaticCredentialsProvider(creds);
        idp = AWSCognitoIdentityProviderClientBuilder.standard()
                .withCredentials(acp).withRegion(Regions.US_EAST_1).build();
    }

    public void getClientRSAKey(Context ctx) {
        RSAPublicKey clientRSAKey = null;
        try {
            String hexClientKey = ctx.formParam("publicKey");
            byte[] byteClientKey = Util.fromHexString(hexClientKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            clientRSAKey = (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(byteClientKey));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        Client c = new Client();
        c.rsaKey = clientRSAKey;
        try {
            c.rsaEncrypter.init(Cipher.ENCRYPT_MODE, c.rsaKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        ctx.result(c.clientKey);
    }

    public void sendAESKey(Context ctx){
        Client c = Client.find(ctx);
        byte[] clientAESKey = c.aesKey.getEncoded();
        byte[] clientIV = c.initializationVectors.getIV();

        Map<String, String> response = null;
        try {
            response = new HashMap<String, String>() {
                {
                    put("key", Util.asHex(c.rsaEncrypter.doFinal(clientAESKey)));
                    put("iv", Util.asHex(c.rsaEncrypter.doFinal(clientIV)));
                }
            };
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        ctx.result(response.toString());
    }

    public void testEncryption(Context ctx){
        Client c = Client.find(ctx);
        try {
            ctx.result(Util.asHex(c.aesEncrypter.doFinal("secure".getBytes())));
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }

    //receive message by looking up client AES key
    public ClientData secureReceive(Context ctx){
        try {
            Client c = Client.find(ctx);
            byte[] encrypted = Util.fromHexString(ctx.formParam("data"));
            byte[] decrypted = c.aesDecrypter.doFinal(encrypted);
            System.out.println("\nSecurely decoded: \n" + new String(decrypted) + "\n");
            return new ClientData(c, new String(decrypted));
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NullPointerException e) {
            System.out.println("Could not match userKey!");
        }
        return null;
    }

    public void secureSend(Context ctx, String data){
        try {
            Client c = Client.find(ctx);
            byte[] encrypted = c.aesEncrypter.doFinal(data.getBytes());
            ctx.result(Util.asHex(encrypted));
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public void signInUser(Context ctx){
        ClientData data = secureReceive(ctx);
        JsonObject jdata = Util.jp.parse(data.data).getAsJsonObject();
        String username = jdata.get("username").getAsString();
        String password = jdata.get("password").getAsString();

        Map<String, String> authParams = new HashMap<String, String>() {
                {
                    put("USERNAME", username);
                    put("PASSWORD", password);
                }
            };

        AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        authRequest.withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .withClientId(awsClientId)
                .withUserPoolId(awsUserPool)
                .withAuthParameters(authParams);

        try{
            AdminInitiateAuthResult r = idp.adminInitiateAuth(authRequest);
            if(r.getChallengeName() != null && r.getChallengeName().equals("NEW_PASSWORD_REQUIRED")) {
                data.client.forceNewPassword = true;
                secureSend(ctx, r.getChallengeName());
                data.client.authSession = r.getSession();
                data.client.authenticatedAsUser = username;
                return;
            }
            data.client.authSession = r.getSession();
        }
        catch(NotAuthorizedException e){
            System.out.println("User " + username + " attempted to log in with incorrect credentials.");
            secureSend(ctx, "UNAUTHORIZED");
            return;
        }
        data.client.authenticatedAsUser = username;
        secureSend(ctx, "HELL YEAH BITCHES THIS SHIT WORKS WOOOOO");
    }

    public void updateUserInfo(Context ctx) {
        ClientData data = secureReceive(ctx);
        JsonObject jdata = Util.jp.parse(data.data).getAsJsonObject();
        String newName = jdata.get("name").getAsString();
        String newpassword = jdata.get("newpassword").getAsString();
        AttributeType nameAttrib = new AttributeType().withName("name").withValue(newName);
        AdminUpdateUserAttributesResult r = idp.adminUpdateUserAttributes(
                new AdminUpdateUserAttributesRequest()
                    .withUserAttributes(nameAttrib)
                    .withUserPoolId(awsUserPool)
                    .withUsername(data.client.authenticatedAsUser));

        Map<String, String> m = new HashMap<>();
        m.put("NEW_PASSWORD", newpassword);
        m.put("USERNAME", data.client.authenticatedAsUser);
        AdminRespondToAuthChallengeResult rr = idp.adminRespondToAuthChallenge(
                new AdminRespondToAuthChallengeRequest()
                    .withChallengeName("NEW_PASSWORD_REQUIRED")
                    .withSession(data.client.authSession)
                    .withUserPoolId(awsUserPool)
                    .withClientId(awsClientId)
                    .withChallengeResponses(m));
        secureSend(ctx, "ALL GOOD HOMIE");
        return;
    }

    public void resetPassword(Context ctx){
        ClientData data = secureReceive(ctx);
        AdminResetUserPasswordResult r = idp.adminResetUserPassword(
                new AdminResetUserPasswordRequest()
                .withUsername(data.client.authenticatedAsUser)
                .withUserPoolId(awsUserPool));
        secureSend(ctx, "ALL GOOD HOMIE");
    }

    public class ClientData{
        //holds decrypted data while still coupling with clientkey
        Client client;
        String data;
        public ClientData(Client c, String d){
            client = c;
            data = d;
        }
    }
}
