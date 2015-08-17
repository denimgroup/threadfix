package com.denimgroup.threadfix.selenium.utils;

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

    //Executes command and returns JSON
    public String executeCommand(String workingDirectory, String... args) {
        String output = "";

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
                    return line;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "No JSON found.";
    }

    public boolean isCommandResponseSuccessful(String response) {
        String status = JsonUtils.getStringProperty(response, "success");
        return ("true").equals(status.trim().toLowerCase()) ? true : false;
    }

    public String executeJarCommand(String... args) {
        return executeCommand(DIRECTORY, args);
    }

    public void setApiKey(String apiKey) {
        executeJarCommand("-set", "key", apiKey);
    }

    public void setUrl(String url) {
        executeJarCommand("-set", "url", url);
    }
}
