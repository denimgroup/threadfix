package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.DefaultRequestConfigurer;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RequestConfigurer;
import com.denimgroup.threadfix.importer.util.DateUtils;
import org.apache.commons.httpclient.HttpMethodBase;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.*;
import java.util.Map.Entry;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
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
        super(ScannerType.APPSCAN_DYNAMIC);
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

        try{
            String sessionId = loginToAppScanEnterprise();

            UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(getAuthenticationFieldValue(URL) + BASE_URL + SCAN_SERVICE);
            uriComponentsBuilder.queryParam("query", "Application Name=" + remoteProviderApplication.getNativeName());
            String url = uriComponentsBuilder.toUriString();

            HttpResponse response = httpUtils.getUrlWithConfigurer(url, getRequestConfigurer(sessionId));
            if(response.isValid()){
                String responseBody = response.getBodyAsString();

                JSONObject json = getJSONObject("{\"issues\": " + responseBody + "}");

                Map<Calendar, List<Finding>> findingMap = new TreeMap<Calendar, List<Finding>>();

                for(JSONObject object : toJSONObjectIterable(json.getString("issues"))){
                    String date = object.getString("18");
                    Calendar cal = getCalendarAtMidnight(date);

                    if(!findingMap.containsKey(cal)){
                        findingMap.put(cal, new ArrayList<Finding>());
                    }

                    Finding finding = getFindingFromObject(object);
                    findingMap.get(cal).add(finding);
                }

                for(Calendar cal : findingMap.keySet()){
                    Scan scan = new Scan();
                    scan.setImportTime(cal);
                    scan.setFindings(new ArrayList<Finding>());

                    for(Entry<Calendar, List<Finding>> entry : findingMap.entrySet()){
                        scan.getFindings().addAll(entry.getValue());

                        if(cal.equals(entry.getKey())){
                            break;
                        }
                    }

                    scans.add(scan);
                }

            }else{
                log.warn("Received a bad response from App Scan Enterprise server, returning null");
                return null;
            }

            logoutFromAppScanEnterprise();
        }catch (RestIOException e){
            log.info("Error while retrieving scans from App Scan Enterprise");
        } catch (JSONException e) {
            log.info("Error while retrieving scans from App Scan Enterprise");
        }

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

        String username = getAuthenticationFieldValue(USERNAME);
        if(username.contains("\\") && !username.contains("\\\\")){
            username = username.replace("\\","\\\\");
        }

        String loginJSON = String.format(LOGIN_JSON_FORMAT, username, getAuthenticationFieldValue(PASSWORD));

        return new DefaultRequestConfigurer()
                .withContentType("application/json")
                .withRequestBody(loginJSON, "application/json");
    }

    private Finding getFindingFromObject(JSONObject object){
        Finding finding = null;

        try{
            Map<FindingKey, String> findingMap = map(
                    FindingKey.VULN_CODE, object.getString("3"),
                    FindingKey.SEVERITY_CODE, object.getString("29"),
                    FindingKey.NATIVE_ID, object.getString("id"),
                    FindingKey.PATH, object.getString("10"),
                    FindingKey.RAWFINDING, object.toString()
            );

            finding = constructFinding(findingMap);
        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received.");
        }
        return finding;
    }

    private Calendar getCalendarAtMidnight(String found) {
        Calendar testedDate = DateUtils.getCalendarFromString("MM/dd/yy hh:mm aa", found);
        if (testedDate != null) {
            testedDate.set(Calendar.HOUR_OF_DAY, 0);
            testedDate.set(Calendar.MINUTE, 0);
            testedDate.set(Calendar.SECOND, 0);
            testedDate.set(Calendar.MILLISECOND, 0);
        }
        return testedDate;
    }

    private RemoteProviderApplication getApplication(JSONObject object) throws JSONException{
        RemoteProviderApplication application = new RemoteProviderApplication();
        application.setNativeName(object.getString("name"));
        application.setNativeId(object.getString("id"));
        application.setRemoteProviderType(remoteProviderType);
        return application;
    }
}
