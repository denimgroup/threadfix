package com.denimgroup.threadfix.selenium.utils;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.controller.AddUserController;

import java.io.File;

import static org.junit.Assert.assertTrue;

/**
 * Created by mac on 3/3/14.
 */
public class DatabaseUtils {

    public static final String API_KEY, REST_URL;
    public static final ThreadFixRestClient CLIENT;

    static {
        API_KEY = System.getProperty("API_KEY");
        REST_URL = System.getProperty("REST_URL");

        CLIENT = new ThreadFixRestClientImpl(REST_URL, API_KEY);

        if (API_KEY == null) {
            throw new IllegalStateException("API_KEY system variable was null.");
        }
        if (REST_URL == null) {
            throw new IllegalStateException("REST_URL system varteiable was null.");
        }
    }

    public static void createTeam(String teamName) {
        RestResponse<Organization> response = CLIENT.createTeam(teamName);

        assertTrue("Response was unsuccessful. Message: " + response.message, response.success);
    }

    public static void createUser(String username, String globalRoleName) {
        RestResponse<User> response = CLIENT.createUser(username, globalRoleName);

        assertTrue("Response was unsuccessful. Message: " + response.message, response.success);
    }

    public static void createUser(String username) {
        RestResponse<User> response = CLIENT.createUser(username);

        assertTrue("Response was unsuccessful. Message: " + response.message, response.success);
    }

    public static void createRole(String roleName, boolean allPermissions) {
        RestResponse<Role> response = CLIENT.createRole(roleName, allPermissions);

        assertTrue("Response was unsuccessful. Message: " + response.message, response.success);
    }

    public static void createApplication(String teamName, String appName) {

        RestResponse<Organization> response = CLIENT.searchForTeamByName(teamName);

        assertTrue("Request for team was unsuccessful. Message: " + response.message, response.success);

        RestResponse<Application> applicationRestResponse = CLIENT.createApplication(String.valueOf(response.object.getId()), appName, "http://test.com");

        assertTrue("Response was unsuccessful. Message: " + applicationRestResponse.message, applicationRestResponse.success);
    }

    public static void uploadScan(String teamName, String appName, String filePath) {
        assertTrue("FilePath is not valid: " + filePath, new File(filePath).exists());
        RestResponse<Application> response = CLIENT.searchForApplicationByName(appName, teamName);
        assertTrue("Request for Application was unsuccessful. Message:" + response.message, response.success);

        RestResponse<Scan> restResponse = CLIENT.uploadScan(String.valueOf(response.object.getId()), filePath);
        assertTrue("Response was unsuccessful. Message: " + restResponse.message, restResponse.success);

    }
}
