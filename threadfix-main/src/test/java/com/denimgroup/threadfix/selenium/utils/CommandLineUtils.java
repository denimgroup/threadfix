package com.denimgroup.threadfix.selenium.utils;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;

import static com.denimgroup.threadfix.CollectionUtils.list;

import com.denimgroup.threadfix.importer.util.JsonUtils;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by rtimmons on 8/17/2015.
 */
public class CommandLineUtils {

    private static List<String> startArgs;
    private static final String DIRECTORY = "..\\threadfix-cli\\target";

    static {
        startArgs = list();
        if (System.getProperty("os.name").startsWith("Windows")) {
            startArgs.add("CMD");
            startArgs.add("/C");
        } else {
            startArgs.add("/bin/sh");
        }
        startArgs.add("java");
        startArgs.add("-jar");
        startArgs.add("threadfix-cli-2.2-SNAPSHOT-jar-with-dependencies.jar");
    }

    // Executes command and returns JSON object
    public JSONObject executeCommand(String workingDirectory, String... args) {
        List<String> finalArgs = new ArrayList<>();
        finalArgs.addAll(startArgs);
        for (String arg : args) {
            finalArgs.add(arg);
        }
        ProcessBuilder pb = new ProcessBuilder(finalArgs);
        pb.directory(new File(workingDirectory));
        try {
            Process process = pb.start();
            InputStream is = process.getInputStream();
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line;

            System.out.println("Output of running command is:");

            while ((line = br.readLine()) != null) {
                System.out.println(line);
                if(line.startsWith("{")){
                    System.out.println("SUCCESS: " + JsonUtils.getStringProperty(line, "success"));
                    return JsonUtils.getJSONObject(line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
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

    public JSONObject searchTeam(String searchBy, String value) {
        return executeJarCommand("-st", searchBy, value);
    }
}
