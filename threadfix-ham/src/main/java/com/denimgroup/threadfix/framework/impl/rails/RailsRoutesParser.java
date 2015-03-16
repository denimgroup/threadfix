package com.denimgroup.threadfix.framework.impl.rails;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Stack;

/**
 * Created by sgerick on 3/9/2015.
 */
public class RailsRoutesParser {
    private static final SanitizedLogger log = new SanitizedLogger("FrameworkCalculator");
    private String fileName = null;
    private Scanner scanner = null;
    private List<String[]> routes = new ArrayList<>();
    private List<String[]> collection = new ArrayList<>();
    private Stack stack = new Stack();
    private String urlPrefix = "/";

    public RailsRoutesParser(String fileName) throws FileNotFoundException {
        this.fileName = fileName;
        scanner = new Scanner(new File(fileName));
        scanner.useDelimiter("(\\p{javaWhitespace}+|,|=>)+");
        stack.push("appStart");
    }

    public List parse() {
        if (scanner == null) {
            log.warn("scanner is null parsing file");
            return null;
        }
        while (scanner.hasNext()) {
            String s = scanner.next();
            parseWord(s);
        }
        return routes;
    }

    private void parseWord(String s) {
        switch (s.toUpperCase()) {
            case "GET":
                doGet();
                break;
            case "MATCH":
                doGet();
                break;
            case "PUT":
                doPut();
                break;
            case "POST":
                doPost();
                break;
            case "DELETE":
                doDelete();
                break;
            case "COLLECTION":
                doCollection();
                break;
            case "RESOURCE":
                doResource();
                break;
            case "RESOURCES":
                doResources();
                break;
            case "NAMESPACE":
                doNamespace();
                break;
            case "END":
                if (stack.empty() || stack.size() < 1) {
                    log.warn("Stack empty when \"END\" tag reached in " + fileName);
                    System.err.println("Stack empty when \"END\" tag reached in " + fileName);
                } else {
                    doEnd((String) stack.pop());
                }
                break;
        }
    }

    private String cleanString(String s) {
        if ((s.startsWith("\"")) && s.endsWith("\""))
            s = s.replaceAll("^\"|\"$", "");
        if (s.startsWith(":"))
            s = s.replaceFirst(":", "");
        if (s.endsWith(","))
            s = s.substring(0, s.length()-1);
        return s;
    }

    private String removeLastPath(String s) {
        if (null != s && s.length() > 1) {
            int endIndex = s.lastIndexOf('/', s.lastIndexOf('/') - 1 ) + 1;
            if (endIndex >= 0) {
                s = s.substring(0, endIndex);
            }
        }
        return s;
    }

    private void doGet() {
        String s = scanner.next();
        s = cleanString(s);
        doUrl("GET", urlPrefix + s);
    }

    private void doPost() {
        String s = scanner.next();
        s = cleanString(s);
        doUrl("POST", urlPrefix + s);
    }

    private void doPut() {
        String s = scanner.next();
        s = cleanString(s);
        doUrl("PUT", urlPrefix + s);
    }

    private void doDelete() {
        String s = scanner.next();
        s = cleanString(s);
        doUrl("DELETE", urlPrefix + s);
    }

    private void doUrl(String method, String url) {
        if (null != url && url.length() > 1) {
            int endIndex = url.lastIndexOf("/");
            if ((endIndex+1) == url.length()) {
                url = url.substring(0, endIndex);
            }
        }
        String[] route = new String[]{method, url};
        routes.add(route);
    }

    private void doCollection() {
        collection.clear();
        while (scanner.hasNext()) {
            String s = scanner.next();
            if ("END".equalsIgnoreCase(s))
                return;
            if ("GET".equalsIgnoreCase(s)
                || "MATCH".equalsIgnoreCase(s)
                || "PUT".equalsIgnoreCase(s)
                || "POST".equalsIgnoreCase(s)
                || "DELETE".equalsIgnoreCase(s)) {
                String[] item = new String[2];
                item[0] = s.toUpperCase();
                s = scanner.next();
                s = cleanString(s);
                item[1] = s;
                collection.add(item);
            }
        }
    }

    private void doResource() {
        stack.push("resource");
        String s = scanner.next();
        s = cleanString(s);
        urlPrefix = urlPrefix + s + "/";
    }

    private void doResources() {
        stack.push("resources");
        String s = scanner.next();
        s = cleanString(s);
        urlPrefix = urlPrefix + s + "/{id}/";
    }

    private void doNamespace() {
        stack.push("namespace");
        String s = scanner.next();
        s = cleanString(s);
        urlPrefix = urlPrefix + s + "/";
    }

    private void doEnd(String endCase) {
        switch (endCase.toUpperCase()) {
            case "RESOURCE":
                for (String[] item:collection) {
                    doUrl(item[0], urlPrefix + item[1]);
                }
                doUrl("GET", urlPrefix);
                doUrl("POST", urlPrefix);
                doUrl("GET", urlPrefix + "new");
                doUrl("GET", urlPrefix + "edit");
                doUrl("PUT", urlPrefix);
                doUrl("DELETE", urlPrefix);
                urlPrefix = removeLastPath(urlPrefix);
                collection.clear();
                break;
            case "RESOURCES":
                if (urlPrefix.endsWith("/{id}/")) {
                    int endIndex = urlPrefix.lastIndexOf("{id}/");
                    urlPrefix = urlPrefix.substring(0, endIndex);
                }
                for (String[] item:collection) {
                    doUrl(item[0], urlPrefix + item[1]);
                }
                doUrl("GET", urlPrefix);
                doUrl("POST", urlPrefix);
                doUrl("GET", urlPrefix + "new");
                doUrl("GET", urlPrefix + "{id}/edit");
                doUrl("GET", urlPrefix + "{id}");
                doUrl("PUT", urlPrefix + "{id}");
                doUrl("DELETE", urlPrefix + "{id}");
                urlPrefix = removeLastPath(urlPrefix);
                collection.clear();
                break;
            case "NAMESPACE":
                urlPrefix = removeLastPath(urlPrefix);
                break;
        }
    }

}
