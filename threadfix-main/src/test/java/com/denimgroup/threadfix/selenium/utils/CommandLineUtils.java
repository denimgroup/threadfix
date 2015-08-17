package com.denimgroup.threadfix.selenium.utils;

import static com.denimgroup.threadfix.CollectionUtils.list;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by rtimmons on 8/17/2015.
 */
public class CommandLineUtils {

    private static List<String> startArgs;
    private static final String DIRECTORY = "..\\threadfix-cli\\target";
    private static final String OS = System.getProperty("OperatingSystem");

    static {
        startArgs = list();
        if (("Windows").equals(OS)) {
            startArgs.add("CMD");
            startArgs.add("/C");
        } else {
            startArgs.add("/bin/sh");
        }
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
            Process process = pb.start();
            InputStream is = process.getInputStream();
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            String line;

            System.out.println("Output of running command is:");

            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
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
