package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

import static com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl.getImpl;

/**
 * Created by skakani on 5/26/2015.
 */
@RemoteProvider(name = "IBM Rational AppScan Enterprise")
public class AppScanEnterpriseRemoteProvider extends AbstractRemoteProvider{
    public static final String
                USERNAME = "Username",
                PASSWORD = "Password",
                URL = "URL",
                BASE_URL = "ase/api/",
                FEATURE_KEY = "AppScanEnterpriseUser",
                LOGIN_SERVICE = "login",
                LOGOUT_SERVICE = "logout",
                APP_SERVICE = "applications";

    public AppScanEnterpriseRemoteProvider() {
      super(ScannerType.APPSCAN_ENTERPRISE);
    }

    RemoteProviderHttpUtils httpUtils = getImpl(AppScanEnterpriseRemoteProvider.class);

    @Override
    public List<RemoteProviderApplication> fetchApplications(){

        return null;

    }

    @Override
    public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication){
        return null;
    }

    private String loginToAppScanEnterprise(){
        assert remoteProviderType != null : "Remote Provider Type is null, Please set it before trying to log in";

        HttpResponse response = httpUtils.postUrl(getAuthenticationFieldValue(URL) + BASE_URL + LOGIN_SERVICE, new String[]{"featureKey"}, new String[]{"AppScanEnterpriseUser"}, getAuthenticationFieldValue(USERNAME), getAuthenticationFieldValue(PASSWORD));
        if(response.isValid()){
            JSONObject jsonObject = new JSONObject(response);
            try{
                return jsonObject.get("sessionId").toString();
            }catch(JSONException e){
                throw new RestIOException(e, "Invalid response received. May not be JSON");
            }
        }else{
            String body = response.getBodyAsString();
            log.info("Rest response from App Scan Enterprise Login Service:" + body);
            throw new RestIOException("Invalid response with following status. Please Check logs for more details", response.getStatus());
        }
    }

    private void logoutFromAppScanEnterprise(){
        assert remoteProviderType != null : "Remote Provider Type is null, You shouldn't be here with out Remote provider. Check why this happened";

        HttpResponse response = httpUtils.getUrl(getAuthenticationFieldValue(URL) + BASE_URL + LOGOUT_SERVICE);
        if(response.isValid()){
            log.info("Successfully logged out from APP SCAN ENTERPRISE");
        }else {
            String body = response.getBodyAsString();
            log.info("Rest response from App Scan Enterprise Logout Service:" + body);
            throw new RestIOException("Invalid response with following status. Please Check logs for more details", response.getStatus());
        }

    }
}
