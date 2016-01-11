////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.service.defects.utils.hpqc;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.exception.DefectTrackerCommunicationException;
import com.denimgroup.threadfix.exception.DefectTrackerFormatException;
import com.denimgroup.threadfix.exception.IllegalStateRestException;
import com.denimgroup.threadfix.exception.RestRedirectException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.utils.MarshallingUtils;
import com.denimgroup.threadfix.service.defects.utils.hpqc.infrastructure.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

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
        con = getRestConnector().init(
                new HashMap<String, String>(),
                serverUrl,
                "",
                "");

        String authenticationPoint = getAuthenticationUrl();
        if (authenticationPoint == null) {
            log.warn("HP Quality Center was invalid, 401 response was expected but 200 returned.");
            return false;
        } else {
            log.info("HP Quality Center URL was valid, returned 401 response as expected because we do not yet have credentials.");
            return true;
        }
    }

    // TODO refactor this out
    private static RestConnector getRestConnector() {
        if (con == null) {
            con = new RestConnector();
        }

        return con;
    }

    public static String getAllProjects(String serverUrl, String username, String password) {
        con = getRestConnector().init(
                new HashMap<String, String>(),
                serverUrl,
                "",
                "");
        log.info("Logging in to HP Quality Center");

        if (!login(username,password)) {
            return "Authentication failed";
        }

        String getProjectsUrl = con.buildUrl("rest/domains?include-projects-info=y");
        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put("Accept", "application/xml");
        Response serverResponse = con.httpGet(getProjectsUrl,
                null, requestHeaders);
        if (serverResponse.getStatusCode() == HttpURLConnection.HTTP_OK) {
            String responseStr = serverResponse.toString();
            if (responseStr.contains("<Domains>")) {
                log.info("Got a list of projects. ");
                return responseStr;
            }
        } else {
            log.warn("Got " + serverResponse.getStatusCode() + " response instead of 200.");
        }

        throw new DefectTrackerCommunicationException("Unable to retrieve projects.");
    }

    public static boolean checkCredentialAndProject(String serverUrl, String username, String password, String domainProject) {
        if (!checkProjectName(serverUrl, domainProject)) {
            return false;
        }

        try {
            log.info("Checking HPQC credentials");
            if (!login(username,password)) {
                return false;
            }

            String[] pDetails = getProjectNameSplit(domainProject);
            String getUrl = con.buildUrl("rest/domains/" + URLEncoder.encode(pDetails[0], "UTF-8")
                    + "/projects/" + URLEncoder.encode(pDetails[1], "UTF-8")
                    + "/customization/users/" + URLEncoder.encode(username, "UTF-8"));

            Response serverResponse = doGet(serverUrl, getUrl, domainProject);

            String responseStr = serverResponse.toString();

            log.debug(responseStr);

            if (responseStr.contains("</User>")) {
                return true;
            } else {
                log.warn("Received response code " + serverResponse.getStatusCode() +
                        " and the response string didn't contain </User>. " +
                        "The user is probably not authenticated for " + domainProject);
            }
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateRestException(e, "UTF-8 not supported.");
        }

        return false;
    }

    public static boolean checkCredential(String serverUrl, String username, String password) {
        return login(username, password);
    }

    @Nullable
    public static Map<String,List<String>> getListValues(String serverUrl, String username, String password, String domainProject) {
        if (!checkProjectName(serverUrl, domainProject)) {
            return null;
        }

        try {
            if (!login(username,password)) {
                return null;
            }

            String[] pDetails = getProjectNameSplit(domainProject);
            String getUrl = con.buildUrl("rest/domains/" + URLEncoder.encode(pDetails[0], "UTF-8")
                    + "/projects/" + URLEncoder.encode(pDetails[1], "UTF-8")
                    + "/customization/entities/defect/lists");

            Response serverResponse = doGet(serverUrl, getUrl, domainProject);

            String responseStr = serverResponse.toString();

            log.debug(responseStr);

            if (responseStr.contains("<Lists>")) {
                return parseListXml(responseStr);
            } else {
                log.warn("XML didn't have <Lists>, returning null.");
            }

            return null;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateRestException(e,
                    "Got UnsupportedEncodingException for UTF-8, this should never happen.");
        }
    }

    @Nonnull
    public static String postDefect(String serverUrl,
                                 String username,
                                 String password,
                                 String domain_project,
                                 String defectXml) {
        log.info("Checking HPQC credentials");
        if (!login(username, password))
            return null;
        String postUrl = con.buildEntityCollectionUrl("defect");

        Response response = doPost(serverUrl, postUrl, domain_project, defectXml);

        String responseStr = response.toString();
        Entity newDefect = parseXml(responseStr, Entity.class);
        String newDefectId = getFieldValue(newDefect, "id");
        if (newDefectId != null && !newDefectId.isEmpty()) {
            log.info("New defect was created in HPQC with Id " + newDefectId);
            return newDefectId;
        } else {
            throw new DefectTrackerCommunicationException("Unable to post defect to HPQC.");
        }
    }

    @Nonnull
    public static Map<Defect,Boolean> getStatuses(List<Defect> defectList,
                                                  String serverUrl, String username,
                                                  String password, String domain_project) {
        Map<Defect,Boolean> returnMap = new HashMap<>();

        if (!checkProjectName(serverUrl, domain_project))
            return returnMap;

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
        }

        return returnMap;
    }

    public static List<Defect> getDefectList(String serverUrl, String username, String password, String domain_project) {
        List<Defect> defectList = list();

        if (!checkProjectName(serverUrl, domain_project))
            return defectList;

        Response serverResponse;

        if (login(username,password)) {
            String defectUrl = con.buildEntityCollectionUrl("defect");
            serverResponse = doGet(serverUrl, defectUrl, domain_project);
            String responseStr = serverResponse.toString();

            log.debug(responseStr);

            if (responseStr.contains("</Entities>")) {
                Entities entities = parseXml(responseStr, Entities.class);
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

        return defectList;
    }

    @Nullable
    public static List<Fields.Field> getEditableFields(String serverUrl, String username, String password, String domainProject) {
        if (!checkProjectName(serverUrl, domainProject)) {
            return null;
        }

        try {
            if (!login(username,password)) {
                return null;
            }

            String[] pDetails = getProjectNameSplit(domainProject);
            String getUrl = con.buildUrl("rest/domains/" + URLEncoder.encode(pDetails[0], "UTF-8")
                    + "/projects/" + URLEncoder.encode(pDetails[1], "UTF-8")
                    + "/customization/entities/defect/fields");

            Response serverResponse = doGet(serverUrl, getUrl, domainProject);

            String responseStr = serverResponse.toString();

            log.debug(responseStr);

            if (responseStr.contains("<Fields>")) {
                return parseFieldXml(responseStr);
            } else {
                log.warn("XML didn't have <Fields>, returning null.");
            }

            return null;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateRestException(e,
                    "Got UnsupportedEncodingException for UTF-8, this should never happen.");
        }
    }

    @Nullable
    public static List<Users.User> getActiveUsers(String serverUrl, String username, String password, String domainProject) {
        if (!checkProjectName(serverUrl, domainProject)) {
            return null;
        }

        try {
            if (!login(username,password)) {
                return null;
            }

            String[] pDetails = getProjectNameSplit(domainProject);
            String getUrl = con.buildUrl("rest/domains/" + URLEncoder.encode(pDetails[0], "UTF-8")
                    + "/projects/" + URLEncoder.encode(pDetails[1], "UTF-8")
                    + "/customization/users");

            Response serverResponse = doGet(serverUrl, getUrl, domainProject);

            String responseStr = serverResponse.toString();

            log.debug(responseStr);

            if (responseStr.contains("<Users>")) {
                Users users = parseXml(responseStr, Users.class);
                return filterUser(users);
            } else {
                log.warn("XML didn't have <Users>, returning null.");
            }

            return null;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateRestException(e,
                    "Got UnsupportedEncodingException for UTF-8, this should never happen.");
        }
    }

    @Nullable
    public static Entities getEntities(String serverUrl, String username, String password, String domainProject, @Nonnull String entityName) {
        if (!checkProjectName(serverUrl, domainProject)) {
            return null;
        }

        try {
            if (!login(username,password)) {
                return null;
            }

            String[] pDetails = getProjectNameSplit(domainProject);
            String getUrl = con.buildUrl("rest/domains/" + URLEncoder.encode(pDetails[0], "UTF-8")
                    + "/projects/" + URLEncoder.encode(pDetails[1], "UTF-8")
                    + "/" + entityName + "s");

            Response serverResponse = doGet(serverUrl, getUrl, domainProject);

            String responseStr = serverResponse.toString();

            log.debug(responseStr);

            if (responseStr.contains("</Entities>")) {
                return parseXml(responseStr, Entities.class);
            } else {
                log.warn("XML didn't have <Users>, returning null.");
            }

            return null;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateRestException(e,
                    "Got UnsupportedEncodingException for UTF-8, this should never happen.");
        }
    }

    @Nonnull
    private static List<Users.User> filterUser(Users users) {

        List<Users.User> result = list();
        if (users != null && users.getUsers() != null) {

            for (Users.User user : users.getUsers()) {
                if (user != null && user.isUserActive()) {
                    result.add(user);
                }
            }
        }

        return result;
    }

    @Nonnull
    private static Response doGet(String serverUrl, String getUrl, String domain_project) {
        if (checkProjectNameAndReset(serverUrl, domain_project)) {
            Map<String, String> requestHeaders = new HashMap<>();
            requestHeaders.put("Accept", "application/xml");

            Response serverResponse = con.httpGet(getUrl, null, requestHeaders);
            if (serverResponse.getStatusCode() == HttpURLConnection.HTTP_OK) {
                return serverResponse;
            } else {
                log.warn("The response for the get request was " + serverResponse.getStatusCode() + ", not 200.");
                throw new DefectTrackerCommunicationException(
                        "Got " + serverResponse.getStatusCode() + " response from server.");
            }
        } else {
            throw new DefectTrackerCommunicationException("Invalid project selected.");
        }
    }

    @Nonnull
    private static Response doPost(String serverUrl, String postUrl, String domainProject, String dataXml) {
        if (checkProjectNameAndReset(serverUrl, domainProject)) {
            Map<String, String> requestHeaders = new HashMap<>();
            requestHeaders.put("Content-Type", "application/xml");
            requestHeaders.put("Accept", "application/xml");

            Response serverResponse = con.httpPost(postUrl, dataXml.getBytes(), requestHeaders);
            int statusCode = serverResponse.getStatusCode();
            if (statusCode == HttpURLConnection.HTTP_OK ||
                    statusCode == HttpURLConnection.HTTP_CREATED ||
                    statusCode == HttpURLConnection.HTTP_ACCEPTED) {
                return serverResponse;
            } else {
                log.warn("The response for the get request was " + serverResponse.getStatusCode() + ", not 200.");
                throw new DefectTrackerCommunicationException(
                        "Got " + getServerErrorMsg(serverResponse) + " response from server.");
            }
        } else {
            throw new DefectTrackerCommunicationException("Invalid project selected.");
        }
    }

    private static String getServerErrorMsg(@Nonnull Response serverResponse) {
        if (serverResponse.toString().contains("<QCRestException>")) {
            QCRestException exception = MarshallingUtils.marshal(QCRestException.class, serverResponse.toString());
            return exception.getId() + ": " + exception.getTitle();
        } else
            return String.valueOf(serverResponse.getStatusCode());
    }

    private static boolean checkProjectName(String serverUrl, String domain_project) {
        String[] pDetails = getProjectNameSplit(domain_project);
        if (pDetails.length != 2) {
            log.warn("domain/project is invalid: " + domain_project);
            return false;
        }
        con = getRestConnector().init(
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
        con = getRestConnector().reset(
                serverUrl,
                pDetails[0],
                pDetails[1]);
        return true;
    }

    private static String getStatus(Defect defect) {
        String defectUrl = con.buildEntityUrl("defect", defect.getNativeId());

        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put("Accept", "application/xml");
        Response serverResponse = con.httpGet(defectUrl, null, requestHeaders);
        if (serverResponse.getStatusCode() == HttpURLConnection.HTTP_OK) {
            String responseStr = serverResponse.toString();
            if (responseStr.contains("</Entity>")) {
                String status = getFieldValue(parseXml(responseStr, Entity.class), "status");
                log.info("Current status for defect " + defect.getNativeId() + " is " + status);
                defect.setStatus(status);
                return status;
            } else {
                log.warn("XML response is incorrect: does not contain <\\Entity>");
            }
        } else {
            log.warn("Response code was " + serverResponse.getStatusCode() + ", not 200.");
        }

        return null;
    }

    @Nullable
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

    @Nonnull
    private static Map<String, List<String>> parseListXml(String responseStr) {
        Map<String, List<String>> map = new HashMap<>();
        Lists lists = marshalWithExceptionClass(Lists.class, responseStr);

        if (lists != null && lists.getLists() != null) {
            for (Lists.ListInfo listInfo : lists.getLists()) {
                if (listInfo != null && listInfo.getItems().getItemList() != null) {
                    List<String> values = list();
                    for (Lists.ListInfo.Item item: listInfo.getItems().getItemList()) {
                        if (item != null) {
                            values.addAll(getItemValues(item));
                        }
                    }
                    map.put(listInfo.getId(), values);
                }
            }
        }
        return map;
    }

    @Nonnull
    private static List<String> getItemValues(Lists.ListInfo.Item item) {
        List<String> values = list();
        if (item != null) {
            values.add(item.getValue());
            if (item.getSubItemList() != null)  {
                for (Lists.ListInfo.Item subItem: item.getSubItemList()) {
                    values.addAll(getItemValues(subItem));
                }
            }
        }
        return values;
    }

    @Nonnull
    private static List<Fields.Field> parseFieldXml(String responseStr) {
        List<Fields.Field> result = list();
        Fields fields = marshalWithExceptionClass(Fields.class, responseStr);
        if (fields != null && fields.getFields() != null) {

            for (Fields.Field field : fields.getFields()) {
                if (field != null && field.isActive() && field.isEditable()) {
                    result.add(field);
                }
            }
        }
        return result;
    }

    @Nullable
    private static <T> T parseXml(String responseStr, Class<T> c) {
        return marshalWithExceptionClass(c, responseStr);
    }

    private static String[] getProjectNameSplit(String domainProject) {
        return domainProject == null ? new String[]{} : domainProject.split("/");
    }

    /**
     * @param username
     * @param password
     * @return true if authenticated at the end of this method.
     *
     * convenience method used by other examples to do their login
     */
    private static boolean login(String username, String password) {

        String authenticationPoint = getAuthenticationUrl();

        boolean isLogin = authenticationPoint.equals(String.valueOf(HttpURLConnection.HTTP_OK)) ||
                (authenticationPoint != null && login(authenticationPoint, username, password));

        if (!isLogin) {
            log.warn("Log-in failed");
        }

        return isLogin;
    }

    /**
     * @param loginUrl
     *            to authenticate at
     * @param username
     * @param password
     * @return true on operation success, false otherwise
     *
     * Logging in to our system is standard http login (basic authentication),
     * where one must store the returned cookies for further use.
     */
    private static boolean login(String loginUrl, String username, String password) {

        // Create a string that looks like:
        // "Basic ((username:password)<as bytes>)<64encoded>"
        byte[] credBytes = (username + ":" + password).getBytes();
        String credEncodedString = "Basic " + DatatypeConverter.printBase64Binary(credBytes);

        Map<String, String> map = new HashMap<String, String>();
        map.put("Authorization", credEncodedString);

        Response response = con.httpGet(loginUrl, null, map);

        if (response.getStatusCode() != 200) {
            log.error("Received response code of " + response.getStatusCode() + " instead of 200.");
        }

        return response.getStatusCode() == HttpURLConnection.HTTP_OK && getQCSession();
    }

    private static boolean getQCSession() {
        String qcsessionurl = con.buildUrl("rest/site-session");
        try {
            Response resp = con.httpPost(qcsessionurl, null, null);
            con.updateCookies(resp);

        } catch (Exception e) {
            throw new DefectTrackerCommunicationException(e, "Unable to get session from server.");
        }
        return true;
    }

    /**
     * @return null if authenticated.<br>
     *         a url to authenticate against if not authenticated.
     */
    private static String getAuthenticationUrl() {

        try {
            String isAuthenticateUrl = con.buildUrl("rest/is-authenticated");
            String ret;

            Response response = con.httpGet(isAuthenticateUrl, null, null);
            int responseCode = response.getStatusCode();

            //if already authenticated
            if (responseCode == HttpURLConnection.HTTP_OK) {

                ret = String.valueOf(HttpURLConnection.HTTP_OK);
            }

            //if not authenticated - get the address where to authenticate
            // via WWW-Authenticate
            else if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED) {

                Iterable<String> authenticationHeader =
                        response.getResponseHeaders().get("WWW-Authenticate");

                // TODO some format checking here
                String newUrl = authenticationHeader.iterator().next().split("=")[1];
                newUrl = newUrl.replace("\"", "");
                newUrl += "/authenticate";
                ret = newUrl;
            }

            //Not ok, not unauthorized. An error, such as 404, or 500
            else {
                throw new DefectTrackerCommunicationException(
                        "Unable to communicate with the HPQC server. Response code was " + responseCode);
            }

            return ret;
        } catch (RestRedirectException e) {

            // The redirect will probably be the place we need to authenticate to.
            // We may need to make this recursive.
            log.info("Got redirected while attempting to authenticate, returning location of redirect.");
            if (e.getTargetUrl() != null) {
                return e.getTargetUrl();
            } else {
                throw e;
            }
        }
    }

    public static <T> T marshalWithExceptionClass(Class<T> c, @Nonnull String xml) {
        QCRestException res;
        try {
            return MarshallingUtils.marshal(c, xml);
        } catch (DefectTrackerFormatException ex) {
            try {
                JAXBContext ctx = JAXBContext.newInstance(QCRestException.class);
                Unmarshaller marshaller = ctx.createUnmarshaller();
                res = (QCRestException) marshaller.unmarshal(new StringReader(xml));
                String errorMsg = res.getId() + ": " + res.getTitle();
                throw new DefectTrackerFormatException(ex, errorMsg);
            } catch (JAXBException e) {
                throw new DefectTrackerFormatException(e, "Unable to parse XML response from server.");
            }
        }
    }

}
