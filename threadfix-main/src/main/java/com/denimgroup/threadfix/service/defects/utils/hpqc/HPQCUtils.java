package com.denimgroup.threadfix.service.defects.utils.hpqc;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.utils.hpqc.infrastructure.*;
import com.denimgroup.threadfix.service.defects.utils.MarshallingUtils;

import javax.xml.bind.JAXBException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by stran on 3/13/14.
 */
public class HPQCUtils {

    private static RestConnector con;

    private static final SanitizedLogger log = new SanitizedLogger(HPQCUtils.class);

    public static boolean checkUrl(String serverUrl) {
        if (serverUrl == null) {
            log.info("URL was invalid.");
            return false;
        }
        try {
            con = RestConnector.getInstance().init(
                    new HashMap<String, String>(),
                    serverUrl,
                    "",
                    "");

            String authenticationPoint = isAuthenticated();
            if (authenticationPoint == null) {
                log.warn("HP Quality Center was invalid, 401 response was expected but 200 returned.");
                return false;
            } else {
                log.info("HP Quality Center URL was valid, returned 401 response as expected because we do not yet have credentials.");
                return true;
            }
        } catch (Exception e) {
            log.warn("HP Quality Center was invalid or some other problem occurred, 401 response was expected but not returned.", e);
            return false;
        }
    }
    public static String getAllProjects(String serverUrl, String username, String password) {
        con = RestConnector.getInstance().init(
                new HashMap<String, String>(),
                serverUrl,
                "",
                "");
        try {
            log.info("Logging in to HP Quality Center");

            if (!login(username,password))
                return "Authentication failed";

            String getProjectsUrl = con.buildUrl("rest/domains?include-projects-info=y");
            Map<String, String> requestHeaders = new HashMap();
            requestHeaders.put("Accept", "application/xml");
            Response serverResponse = con.httpGet(getProjectsUrl,
                    null, requestHeaders);
            if (serverResponse.getStatusCode() == HttpURLConnection.HTTP_OK) {
                String responseStr = serverResponse.toString();
                if (responseStr.contains("<Domains>")) {
                    log.info("Got a list of projects. ");
//                    logout();
                    return responseStr;
                }
            } else {
                log.warn("Domains not found");
            }

        } catch (Exception e) {
            log.error("Error when trying to read projects from HP Quality Center");
        }
        return null;
    }

    public static boolean checkCredential(String serverUrl, String username, String password, String domain_project) {
        if (!checkProjectName(serverUrl, domain_project))
            return false;
        try {
            log.info("Checking HPQC credentials");
            if (!login(username,password))
                return false;
            String[] pDetails = getProjectNameSplit(domain_project);
            String getUrl = con.buildUrl("rest/domains/" + pDetails[0]
                    + "/projects/" + pDetails[1]
                    + "/customization/users/" + username);

            Response serverResponse = doGet(serverUrl, getUrl, domain_project);
            if (serverResponse != null) {
                String responseStr = serverResponse.toString();
                if (responseStr.contains("</User>")) {
                    return true;
                } else {
                    log.warn("This credential doesn't have permission with project " + domain_project);
                }
            }
        } catch (Exception e) {
            log.warn("Error when trying to login HPQC");
        }
        return false;
    }

    public static Map<String,List<String>> getListValues(String serverUrl, String username, String password, String domain_project) {
        if (!checkProjectName(serverUrl, domain_project))
            return null;
        try {
            if (!login(username,password))
                return null;

            String[] pDetails = getProjectNameSplit(domain_project);
            String getUrl = con.buildUrl("rest/domains/" + pDetails[0]
                    + "/projects/" + pDetails[1]
                    + "/customization/entities/defect/lists");

            Response serverResponse = doGet(serverUrl, getUrl, domain_project);
            if (serverResponse != null) {
                String responseStr = serverResponse.toString();
                if (responseStr.contains("<Lists>")) {
                    return parseListXml(responseStr);
                } else {
                    log.warn("XML response is incorrect");
                }
            }
        } catch (Exception e) {
            log.warn("Error when trying to login HPQC");
        }
        return null;
    }

    public static String postDefect(String serverUrl,
                                 String username,
                                 String password,
                                 String domain_project,
                                 String defectXml) {
        try {
            log.info("Checking HPQC credentials");
            if (!login(username,password))
                return null;
            String postUrl = con.buildEntityCollectionUrl("defect");

            Response response = doPost(serverUrl, postUrl, domain_project, defectXml);

            if (response != null) {
            String responseStr = response.toString();
            Entity newDefect = parseEntityXml(responseStr);
            String newDefectId = getFieldValue(newDefect, "id");
            if (newDefectId != null && !newDefectId.isEmpty()) {
                log.info("New defect was created in HPQC with Id " + newDefectId);
                return newDefectId;
            }
            }
        } catch (Exception e) {
            log.warn("Error when trying to login HPQC");
        }
        return null;
    }

    public static Map<Defect,Boolean> getStatuses(List<Defect> defectList,
                                                  String serverUrl, String username,
                                                  String password, String domain_project) {
        Map<Defect,Boolean> returnMap = new HashMap<>();

        if (!checkProjectName(serverUrl, domain_project))
            return returnMap;

        try {
            if (login(username,password)) {
                for (Defect defect : defectList) {
                    if (defect != null) {
                        String result = getStatus(defect);
                        defect.setStatus(result);
                        boolean isOpen = result != null &&
                                (!result.equals("Closed") || !result.equals("Fixed") || !result.equals("Rejected"));
                        returnMap.put(defect, isOpen);
                    }
                }
//                logout();
            }
        } catch (Exception e) {
            log.warn("Error when trying to login HPQC");
        }
        return returnMap;
    }

    public static List<Defect> getDefectList(String serverUrl, String username, String password, String domain_project) {
        List<Defect> defectList = new ArrayList<>();
        String defectUrl = con.buildEntityCollectionUrl("defect");

        Response serverResponse;
        try {
            if (login(username,password)) {
                serverResponse = doGet(serverUrl, defectUrl, domain_project);
                if (serverResponse != null) {
                    String responseStr = serverResponse.toString();
                    if (responseStr.contains("</Entities>")) {
                        Entities entities = parseEntitiesXml(responseStr);
                        if (entities.getEntities() != null) {
                            for (Entity entity: entities.getEntities()) {
                                Defect defect = new Defect();
                                defect.setNativeId(getFieldValue(entity, "id"));
                                defectList.add(defect);
                            }
                        }
                    } else {
                        log.warn("XML response is incorrect");
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Error when trying to login HPQC");
        }

        return defectList;
    }

    private static Response doGet(String serverUrl, String getUrl, String domain_project) {
        if (checkProjectNameAndReset(serverUrl, domain_project)) {
            Map<String, String> requestHeaders = new HashMap<>();
            requestHeaders.put("Accept", "application/xml");
            try {
                Response serverResponse = con.httpGet(getUrl,
                        null, requestHeaders);
//                logout();
                if (serverResponse.getStatusCode() == HttpURLConnection.HTTP_OK)
                    return serverResponse;
                else
                    log.warn("The response for the get request was not 200");
            } catch (Exception e) {
                log.warn("Error when trying to get information from HPQC");
            }
        }
        return  null;
    }

    private static Response doPost(String serverUrl, String postUrl, String domain_project, String dataXml) {
        if (checkProjectNameAndReset(serverUrl, domain_project)) {
            Map<String, String> requestHeaders = new HashMap<>();
            requestHeaders.put("Content-Type", "application/xml");
            requestHeaders.put("Accept", "application/xml");

            Response response;
            try {
                response = con.httpPost(postUrl,
                        dataXml.getBytes(), requestHeaders);
                Exception failure = response.getFailure();
                if (failure != null) {
                    log.warn("Error when trying to send a post request", failure);
                } else
                    return response;
            } catch (Exception e) {
                log.warn("Error when trying to send a post request");
            }
        }
        return null;
    }

    private static boolean checkProjectName(String serverUrl, String domain_project) {
        String[] pDetails = getProjectNameSplit(domain_project);
        if (pDetails.length != 2) {
            log.warn("domain/project is invalid");
            return false;
        }
        con = RestConnector.getInstance().init(
                new HashMap<String, String>(),
                serverUrl,
                pDetails[0],
                pDetails[1]);
        return true;
    }

    private static boolean checkProjectNameAndReset(String serverUrl, String domain_project) {
        String[] pDetails = getProjectNameSplit(domain_project);
        if (pDetails.length != 2) {
            log.warn("domain/project is invalid");
            return false;
        }
        con = RestConnector.getInstance().reset(
                serverUrl,
                pDetails[0],
                pDetails[1]);
        return true;
    }

    private static String getStatus(Defect defect) {
        String defectUrl = con.buildEntityUrl("defect", defect.getNativeId());

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put("Accept", "application/xml");
        Response serverResponse = null;
        try {
            serverResponse = con.httpGet(defectUrl,
                    null, requestHeaders);
            if (serverResponse.getStatusCode() == HttpURLConnection.HTTP_OK) {
                String responseStr = serverResponse.toString();
                if (responseStr.contains("</Entity>")) {
                    String status = getFieldValue(parseEntityXml(responseStr), "status");
                    log.info("Current status for defect " + defect.getNativeId() + " is " + status);
                    defect.setStatus(status);
                    return status;
                } else {
                    log.warn("XML response is incorrect");
                }
            } else {
                log.warn("URL not found");
            }
        } catch (Exception e) {
            log.warn("Error when trying to get status of Defect Id " + defect.getNativeId() + " from HPQC");
        }

        return null;
    }

    private static Entity parseEntityXml(String entityXml) {
        try {
            return MarshallingUtils.marshal(Entity.class, entityXml);
        } catch (JAXBException e) {
            log.error("Error when trying to parse Entity from string xml");
        }
        return  null;
    }

    private static Entities parseEntitiesXml(String entitiesXml) {
        try {
            return MarshallingUtils.marshal(Entities.class, entitiesXml);
        } catch (JAXBException e) {
            log.error("Error when trying to parse Entity from string xml");
        }
        return  null;
    }

    private static String getFieldValue(Entity entity, String fieldName) {
        if (entity != null && entity.getFields().getField() != null) {
            for (Entity.Fields.Field field : entity.getFields().getField()) {
                if (field.getName()!= null &&
                        field.getName().equalsIgnoreCase(fieldName) &&
                        field.getValue().size() > 0) {
                    return field.getValue().get(0);
                }
            }
        }
        return null;
    }

    private static Map<String, List<String>> parseListXml(String responseStr) {
        Lists lists;
        Map<String, List<String>> map = new HashMap<>();
        try {
            lists =
                    MarshallingUtils.marshal(Lists.class, responseStr);
            if (lists != null && lists.getLists() != null) {
                for (Lists.ListInfo listInfo : lists.getLists()) {
                    if (listInfo != null && listInfo.getItems().getItemList() != null) {
                        List<String> values = new ArrayList<>();
                        for (Lists.ListInfo.Item item: listInfo.getItems().getItemList()) {
                            if (item != null) {
                                values.add(item.getValue());
                            }
                        }
                        map.put(listInfo.getName(), values);
                    }
                }
            }
        } catch (JAXBException e) {
            log.warn("Error when trying to parsing xml response from HPQC");
            e.printStackTrace();
        }
        return map;
    }

    private static String[] getProjectNameSplit(String domain_project) {
        return domain_project.split("/");
    }

    /**
     * @param username
     * @param password
     * @return true if authenticated at the end of this method.
     * @throws Exception
     *
     * convenience method used by other examples to do their login
     */
    private static boolean login(String username, String password) throws Exception {

        String authenticationPoint = isAuthenticated();
        if (authenticationPoint != null) {
            boolean isLogin = login(authenticationPoint, username, password);
            if (!isLogin)
                log.warn("Log-in failed");
            return isLogin;
        }
        return true;
    }

    /**
     * @param loginUrl
     *            to authenticate at
     * @param username
     * @param password
     * @return true on operation success, false otherwise
     * @throws Exception
     *
     * Logging in to our system is standard http login (basic authentication),
     * where one must store the returned cookies for further use.
     */
    private static boolean login(String loginUrl, String username, String password)
            throws Exception {

        //create a string that lookes like:
        // "Basic ((username:password)<as bytes>)<64encoded>"
        byte[] credBytes = (username + ":" + password).getBytes();
        String credEncodedString = "Basic " + Base64Encoder.encode(credBytes);

        Map<String, String> map = new HashMap<String, String>();
        map.put("Authorization", credEncodedString);

        Response response = con.httpGet(loginUrl, null, map);

        boolean ret = response.getStatusCode() == HttpURLConnection.HTTP_OK;

        return ret;
    }

    /**
     * @return true if logout successful
     * @throws Exception
     *             close session on server and clean session cookies on client
     */
    private static boolean logout() throws Exception {

        //note the get operation logs us out by setting authentication cookies to:
        // LWSSO_COOKIE_KEY="" via server response header Set-Cookie
        Response response =
                con.httpGet(con.buildUrl("authentication-point/logout"),
                        null, null);

        return (response.getStatusCode() == HttpURLConnection.HTTP_OK);

    }

    /**
     * @return null if authenticated.<br>
     *         a url to authenticate against if not authenticated.
     * @throws Exception
     */
    private static String isAuthenticated() throws Exception {

        String isAuthenticateUrl = con.buildUrl("rest/is-authenticated");
        String ret;

        Response response = con.httpGet(isAuthenticateUrl, null, null);
        int responseCode = response.getStatusCode();

        //if already authenticated
        if (responseCode == HttpURLConnection.HTTP_OK) {

            ret = null;
        }

        //if not authenticated - get the address where to authenticate
        // via WWW-Authenticate
        else if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {

            Iterable<String> authenticationHeader =
                    response.getResponseHeaders().get("WWW-Authenticate");

            String newUrl =
                    authenticationHeader.iterator().next().split("=")[1];
            newUrl = newUrl.replace("\"", "");
            newUrl += "/authenticate";
            ret = newUrl;
        }

        //Not ok, not unauthorized. An error, such as 404, or 500
        else {

            throw response.getFailure();
        }

        return ret;
    }


}
