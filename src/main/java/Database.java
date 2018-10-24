import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.model.*;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.*;
import com.amazonaws.services.dynamodbv2.document.spec.GetItemSpec;
import com.google.gson.JsonObject;
import io.javalin.Context;

import java.security.SecureRandom;
import java.util.List;

public class Database {
    DynamoDB db;
    Authentication auth;
    public Database(Authentication a){
        auth = a;
        AmazonDynamoDBClientBuilder bdb = AmazonDynamoDBClientBuilder.standard();
        bdb.withRegion(Regions.US_EAST_1);
        bdb.withCredentials(auth.acp);
        db = new DynamoDB(bdb.build());
    }

    public void createGroup(Context ctx){
        Authentication.ClientData data = auth.secureReceive(ctx);
        JsonObject jdata = Util.jp.parse(data.data).getAsJsonObject();
        String newGroup = createGroupCode();

        Table t = db.getTable("group");
        t.putItem(new Item().withPrimaryKey("id", newGroup).withString("name", jdata.get("name").getAsString()));

        createAdmin(jdata.get("email").getAsString(), newGroup);
        auth.secureSend(ctx, "AIGHT LOL");
    }

	//todo: make sure group doesn't already exist
    public String createGroupCode(){
        SecureRandom sr = new SecureRandom();
        return String.format("%06d", sr.nextInt(1000000));
	}
    
	
    public String createRandomNumbers(){
        SecureRandom sr = new SecureRandom();
        return String.format("%12d", sr.nextLong());
    }

    public void createAdmin(String email, String groupcode){
        auth.idp.adminCreateUser(new AdminCreateUserRequest()
                .withUserPoolId(Authentication.awsUserPool)
                .withUsername(email)
                .withUserAttributes(
                        new AttributeType().withName("custom:groupID").withValue(groupcode),
                        new AttributeType().withName("email").withValue(email))
                .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL));
    }

    public void addAdminToGroup(Context ctx) {
        Authentication.ClientData data = auth.secureReceive(ctx);
        String newAdmin = data.data;
        String toGroup = getGroupByEmail(data.client.authenticatedAsUser);
        createAdmin(newAdmin, toGroup);
    }

    public String getGroupByEmail(String adminEmail){
        AdminGetUserResult thisAdmin = auth.idp.adminGetUser(new AdminGetUserRequest()
                .withUserPoolId(Authentication.awsUserPool)
                .withUsername(adminEmail));
        List<AttributeType> bullshitList = thisAdmin.getUserAttributes();
        for (AttributeType a : bullshitList){
            if(a.getName().equals("custom:groupID"))
                return a.getValue();
        }
        return null;
    }

    public String getAdminName(String adminEmail){
        AdminGetUserResult thisAdmin = auth.idp.adminGetUser(new AdminGetUserRequest()
                .withUserPoolId(Authentication.awsUserPool)
                .withUsername(adminEmail));
        List<AttributeType> bullshitList = thisAdmin.getUserAttributes();
        for (AttributeType a : bullshitList){
            if(a.getName().equals("name"))
                return a.getValue();
        }
        return null;
    }

    public void getGroupByID(Context ctx){
        Authentication.ClientData data = auth.secureReceive(ctx);
        Table t = db.getTable("group");
        GetItemSpec s = new GetItemSpec().withPrimaryKey("id", data.data);
        auth.secureSend(ctx, t.getItem(s).getString("name"));
    }

    public void getGroupInfo(Context ctx){
        Authentication.ClientData data = auth.secureReceive(ctx);
        String groupID = getGroupByEmail(data.client.authenticatedAsUser);

        Table t = db.getTable("group");
        GetItemSpec s = new GetItemSpec().withPrimaryKey("id", groupID);
        String groupName = t.getItem(s).getString("name");

        JsonObject jay = new JsonObject();
        jay.addProperty("id", groupID);
        jay.addProperty("name", groupName);
        auth.secureSend(ctx, jay.toString());
    }

    public void getAdminGroupInfo(Context ctx){
        Authentication.ClientData data = auth.secureReceive(ctx);
        String groupID = getGroupByEmail(data.client.authenticatedAsUser);

        Table t = db.getTable("group");
        GetItemSpec s = new GetItemSpec().withPrimaryKey("id", groupID);
        String groupName = t.getItem(s).getString("name");

        JsonObject jay = new JsonObject();
        jay.addProperty("id", groupID);
        jay.addProperty("name", groupName);
        jay.addProperty("adminName", getAdminName(data.client.authenticatedAsUser));
        auth.secureSend(ctx, jay.toString());
    }

    public void addUserToGroup(Context ctx) {
        Authentication.ClientData data = auth.secureReceive(ctx);
		String groupcode = data.data;
		String newusername = createRandomNumbers();
		String newpassword = createRandomNumbers();
        auth.idp.adminCreateUser(new AdminCreateUserRequest()
                .withUserPoolId(Authentication.awsUserPool)
                .withUsername(newusername)
				.withTemporaryPassword(newpassword)
                .withUserAttributes(
                        new AttributeType().withName("custom:groupID").withValue(groupcode)));

        JsonObject jay = new JsonObject();
        jay.addProperty("username", newusername);
        jay.addProperty("password", newpassword);
        auth.secureSend(ctx, jay.toString());
    }
}
