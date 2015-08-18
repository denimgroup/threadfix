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

    //===========================================================================================================
    // REST Actions
    //===========================================================================================================

    public JSONObject createTeam(String teamName) {
        return executeJarCommand("-ct", teamName);
    }

    public JSONObject createApplication(int teamId, String appName, String appUrl) {
        return executeJarCommand("-ca", String.valueOf(teamId), appName, appUrl);
    }
}
