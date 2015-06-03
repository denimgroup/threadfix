package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.DefaultRequestConfigurer;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RequestConfigurer;
import org.apache.commons.httpclient.HttpMethodBase;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl.getImpl;
import static com.denimgroup.threadfix.importer.util.JsonUtils.getJSONObject;
import static com.denimgroup.threadfix.importer.util.JsonUtils.toJSONObjectIterable;

/**
 * Created by skakani on 5/26/2015.
 */
@RemoteProvider(name = "IBM Rational AppScan Enterprise")
public class AppScanEnterpriseRemoteProvider extends AbstractRemoteProvider{
    public static final String
                USERNAME = "Username",
                PASSWORD = "Password",
                URL = "URL",
                BASE_URL = "/ase/api",
                FEATURE_KEY = "AppScanEnterpriseUser",
                LOGIN_SERVICE = "/login",
                LOGOUT_SERVICE = "/logout",
                APP_SERVICE = "/applications",
                SCAN_SERVICE = "/issues",
                LOGIN_JSON_FORMAT = "{ \"userId\": \"%s\", \"password\": \"%s\", \"featureKey\": \"AppScanEnterpriseUser\"}",
                SESSION_ID = "asc_xsrf_token";

    public AppScanEnterpriseRemoteProvider() {
      super(ScannerType.APPSCAN_ENTERPRISE);
    }

    RemoteProviderHttpUtils httpUtils = getImpl(AppScanEnterpriseRemoteProvider.class);
    private final String EMPTY_URL = "";

    @Override
    public List<RemoteProviderApplication> fetchApplications(){

        assert remoteProviderType != null : "Remote Provider Type is null, Please set it before trying to log in";
        String sessionId = loginToAppScanEnterprise();
        String url = getAuthenticationFieldValue(URL) + BASE_URL + APP_SERVICE + "?columns=name%2Curl";

        //Add Request Headers - Session id and Range
        DefaultRequestConfigurer requestConfigurer = getRequestConfigurerWithHeaderSet(new DefaultRequestConfigurer(), new String[]{SESSION_ID,"Range"}, new String[]{sessionId,"items=0-99"});
        HttpResponse response = httpUtils.getUrlWithConfigurer(url,requestConfigurer);

        if(response.isValid()){
            List<RemoteProviderApplication> applicationList = list();
            try {
                for (JSONObject jsonObject : toJSONObjectIterable(response.getBodyAsString())) {
                    applicationList.add(getApplication(jsonObject));
                }
                logoutFromAppScanEnterprise();
                return applicationList;
            }catch(JSONException e){
                throw new RestIOException(e, "Json Exception occurred");
            }
        }else {
            log.info("Invalid response contents:"+response.getBodyAsString());
            throw new RestIOException("Invalid response from APP SCAN Enterprise:", response.getStatus());
        }

    }

    @Override
    public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication){

        List<Scan> scans = list();

//        try{
            String sessionId = loginToAppScanEnterprise();
//
//            String url = getAuthenticationFieldValue(URL) + BASE_URL + SCAN_SERVICE + "?Application Name=" + remoteProviderApplication.getNativeName();
//
//            HttpResponse response = httpUtils.getUrlWithConfigurer(url, getRequestConfigurer(sessionId));
//
//            if(response.isValid()){
//                JSONObject json = getJSONObject(response.getBodyAsString());
//
//        JSONObject json = getJSONObject(TESTDATA);
//
//        List<Finding> findings = list();
//
//        for(JSONObject object : toJSONObjectIterable(json.getString("data"))){

//        }

//            }else{
//                log.warn("Received a bad response from App Scan Enterprise server, returning null");
//                return null;
//            }
//
//            logoutFromAppScanEnterprise();
//        }catch (RestIOException e){
//            log.info("Error while retrieving scans from App Scan Enterprise");
//        }

        return scans;
    }

    private String loginToAppScanEnterprise(){
        assert remoteProviderType != null : "Remote Provider Type is null, Please set it before trying to log in";

        HttpResponse response = httpUtils.postUrlWithConfigurer(getAuthenticationFieldValue(URL) + BASE_URL + LOGIN_SERVICE, getLoginRequestConfigurer());
        if(response.isValid()){
            String responseBody = response.getBodyAsString();

            JSONObject jsonObject = getJSONObject(responseBody);
            try{
                return jsonObject.get("sessionId").toString();
            }catch(JSONException e){
                throw new RestIOException(e, "Invalid response received. May not be JSON");
            }
        }else{
            String body = response.getBodyAsString();
            log.info("Rest response from App Scan Enterprise Login Service:" + body);
            throw new RestIOException("Invalid response. Please enter correct credentials. Check logs for more details", response.getStatus());
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
            throw new RestIOException("Invalid response. Please Check logs for more details", response.getStatus());
        }

    }

    private DefaultRequestConfigurer getRequestConfigurerWithHeaderSet(DefaultRequestConfigurer requestConfigurer, String[] headerNames, String[] headerValues){
        requestConfigurer.withHeaders(headerNames, headerValues);
        return  requestConfigurer;

    }

    private RequestConfigurer getRequestConfigurer(final String sessionId){

        return new RequestConfigurer() {

            @Override
            public void configure(HttpMethodBase method) {
                method.setRequestHeader("asc_xsrf_token", sessionId);
            }
        };
    }

    private RequestConfigurer getLoginRequestConfigurer(){

        String loginJSON = String.format(LOGIN_JSON_FORMAT, getAuthenticationFieldValue(USERNAME), getAuthenticationFieldValue(PASSWORD));

        return new DefaultRequestConfigurer()
                .withContentType("application/json")
                .withRequestBody(loginJSON, "application/json");
    }

    private RemoteProviderApplication getApplication(JSONObject object) throws JSONException{
        RemoteProviderApplication application = new RemoteProviderApplication();
        application.setNativeName(object.getString("name"));
        application.setNativeId(object.getString("name"));
        application.setReportUrl(object.has("url")?object.getString("url"): EMPTY_URL);
        return application;
    }

}
