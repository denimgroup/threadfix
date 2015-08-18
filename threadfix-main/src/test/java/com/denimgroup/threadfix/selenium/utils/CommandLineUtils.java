package com.denimgroup.threadfix.selenium.utils;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.json.JSONException;
import org.json.JSONObject;

import static com.denimgroup.threadfix.CollectionUtils.list;

import com.denimgroup.threadfix.importer.util.JsonUtils;

import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

/**
 * Created by rtimmons on 8/17/2015.
 */
public class CommandLineUtils {
    protected final SanitizedLogger log = new SanitizedLogger(CommandLineUtils.class);

    private static List<String> startArgs = list();
    private static final String DIRECTORY = ".." + File.separator + "threadfix-cli" + File.separator + "target";

    static {
        if (System.getProperty("os.name").startsWith("Windows")) {
            startArgs.add("CMD");
            startArgs.add("/C");
        } else {
            startArgs.add("bash");
            startArgs.add("-c");
        }
        startArgs.add("java");
        startArgs.add("-jar");
        startArgs.add("threadfix-cli-2.2-SNAPSHOT-jar-with-dependencies.jar");
    }

    // Executes command and returns JSON object
    public JSONObject executeCommand(String workingDirectory, String... args) {
        JSONObject jsonResponse = null;

        List<String> finalArgs = new ArrayList<>();
        finalArgs.addAll(startArgs);
        Collections.addAll(finalArgs, args);
        ProcessBuilder processBuilder = new ProcessBuilder(finalArgs);
        processBuilder.directory(new File(workingDirectory));
        try {
            Process process = processBuilder.start();
            InputStream inputStream = process.getInputStream();
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
            String line;

            System.out.println("Output of running command is:");

            while ((line = bufferedReader.readLine()) != null) {
                System.out.println(line);
                if (line.startsWith("{")) {
                    System.out.println("SUCCESS: " + JsonUtils.getStringProperty(line, "success"));
                    jsonResponse = JsonUtils.getJSONObject(line);
                    return jsonResponse;
                }
            }
        } catch (IOException e) {
            log.error("Process Build command could not be executed gracefully.", e);
        }
        return jsonResponse;
    }

    public JSONObject executeJarCommand(String... args) {
        return executeCommand(DIRECTORY, args);

    }

    public boolean isCommandResponseSuccessful(JSONObject response) {
        try {
            return response.getBoolean("success");
        } catch (JSONException e) {
            e.printStackTrace();
            return false;
        }
    }

    public void setApiKey(String apiKey) {
        executeJarCommand("-set", "key", apiKey);
    }

    public void setUrl(String url) {
        executeJarCommand("-set", "url", url);
    }

    public int getObjectId(JSONObject object) {
        try {
            return object.getJSONObject("object").getInt("id");
        } catch (JSONException e) {
            e.printStackTrace();
            return 0;
        }
    }

    public String getObjectField(JSONObject object, String field) {
        try {
            return object.getJSONObject("object").getString(field);
        } catch (JSONException e) {
            e.printStackTrace();
            return "Field does not exist";
        }
    }

    //===========================================================================================================
    // REST Actions
    //===========================================================================================================

    public JSONObject createTeam(String teamName) {
        return executeJarCommand("-ct", teamName);
    }

    public JSONObject createApplication(int teamId, String appName, String appUrl) {
        return executeJarCommand("-ca", String.valueOf(teamId), appName, appUrl);
    }

    public JSONObject createWaf(String wafName, String wafType) {
        return executeJarCommand("-cw", wafName, wafType);
    }

    public JSONObject searchTagByName(String tagName) {
        return executeJarCommand("-stg", "name", tagName);
    }

    public JSONObject uploadScanFile(int applicationId, String filepath) {
        return executeJarCommand("-u", String.valueOf(applicationId), filepath);
    }

    public JSONObject createTag(String tagName) {
        return executeJarCommand("-ctg", tagName);
    }

    public JSONObject createTag(String tagName, String tagType) {
        return executeJarCommand("-ctg", tagName, tagType);
    }

    public JSONObject searchTeamByID(String id) {
        return executeJarCommand("-st", "id", id);
    }

    public JSONObject searchTeamByName(String name) {
        return executeJarCommand("-st", "name", name);
    }

    public JSONObject searchAppByID(String id) {
        return executeJarCommand("-sa", "id", id);
    }

    public JSONObject searchAppByName(String appName, String teamName) {
        return executeJarCommand("-sa", "name", appName, teamName);
    }

    public JSONObject searchAppByUniqueID(String id, String teamName) {
        return executeJarCommand("-sa", "uniqueId", id, teamName);
    }

    public JSONObject searchWafByID(String id) {
        return executeJarCommand("-sw", "id", id);
    }

    public JSONObject searchWafByName(String name) {
        return executeJarCommand("-sw", "name", name);
    }

    public JSONObject getWafRules(int wafId) {
        return executeJarCommand("-r", String.valueOf(wafId));
    }

    public JSONObject queueScan(int appId, String scannerName) {
        return executeJarCommand("-q", String.valueOf(appId), scannerName);
    }

    public JSONObject addUrlToApp(int appId, String url) {
        return executeJarCommand("-au", String.valueOf(appId), url);
    }

    public JSONObject setTaskConfigFile(int appId, String scanner, String filepath) {
        return executeJarCommand("-stc", String.valueOf(appId), scanner, filepath);
    }

    public JSONObject setParameters(int appId, String framework) {
        return executeJarCommand("-sp", String.valueOf(appId), framework);
    }

    public JSONObject setParameters(int appId, String framework, String repositoryUrl) {
        return executeJarCommand("-sp", String.valueOf(appId), framework, repositoryUrl);
    }

    public JSONObject addTagToApplication(int appId, int tagId) {
        return executeJarCommand("-aat", String.valueOf(appId), String.valueOf(tagId));
    }
}
