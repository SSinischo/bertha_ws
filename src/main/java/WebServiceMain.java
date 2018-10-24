import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import io.javalin.Javalin;

public class WebServiceMain{

    public static void main(String[] args) throws Exception {
        Javalin app = Javalin.create().start(80);
        Authentication auth = new Authentication();
        Database db = new Database(auth);

        app.before(ctx->{
           System.out.println("A client is attempting to reach: " + ctx.path());
           System.out.println(ctx.formParamMap());
        });
        app.put("/keyexchange/rsa", ctx -> auth.getClientRSAKey(ctx));
        app.put("/keyexchange/aes", ctx -> auth.sendAESKey(ctx));
        app.put("/keyexchange/test", ctx -> auth.testEncryption(ctx));
        app.put("/signin", ctx -> auth.signInUser(ctx));
        app.put("/admin/updateinfo", ctx->auth.updateUserInfo(ctx));
        app.put("/admin/resetpassword", ctx->auth.resetPassword(ctx));
        app.put("/admin/creategroup", ctx->db.createGroup(ctx));
        app.put("/admin/inviteadmin", ctx->db.addAdminToGroup(ctx));
        app.put("/admin/groupinfo", ctx->db.getGroupInfo(ctx));
        app.put("/admin/admingroupinfo", ctx->db.getAdminGroupInfo(ctx));
        app.put("/user/lookup", ctx->db.getGroupByID(ctx));
        app.put("/user/join", ctx->db.addUserToGroup(ctx));
    }
}
