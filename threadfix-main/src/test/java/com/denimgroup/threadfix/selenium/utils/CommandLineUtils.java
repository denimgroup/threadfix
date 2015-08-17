package com.denimgroup.threadfix.selenium.utils;

import static com.denimgroup.threadfix.CollectionUtils.list;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by rtimmons on 8/17/2015.
 */
public class CommandLineUtils {

    private static List<String> startArgs;
    private static final String DIRECTORY = "C:\\Users\\rtimmons\\threadfix\\threadfix-cli\\target";

    static {
        startArgs = list();
        startArgs.add("CMD");
        startArgs.add("/C");
        startArgs.add("java");
        startArgs.add("-jar");
        startArgs.add("threadfix-cli-2.2-SNAPSHOT-jar-with-dependencies.jar");
    }

    public void executeCommand(String workingDirectory, String... args) {
        List<String> finalArgs = new ArrayList<>();
        finalArgs.addAll(startArgs);
        for (String arg : args) {
            finalArgs.add(arg);
        }
        ProcessBuilder pb = new ProcessBuilder(finalArgs);
        pb.directory(new File(workingDirectory));
        try {
            pb.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void executeJarCommand(String... args) {
        executeCommand(DIRECTORY, args);
    }

    public void setApiKey(String apiKey) {
        executeJarCommand("-set", "key", apiKey);
    }

    public void setUrl(String url) {
        executeJarCommand("-set", "url", url);
    }
}
