package com.denimgroup.threadfix.properties;


import java.io.*;
import java.util.Properties;

public class PropertiesManager {

    private String url = null;
    private String key = null;
    private Properties properties;

    private static final PropertiesManager INSTANCE = new PropertiesManager();

    private PropertiesManager(){}

    // this allows us to switch implementations later
    public static PropertiesManager getInstance() {
        return INSTANCE;
    }

    public void setUrl(String url) {
        writeProperty("url", url);
    }

    public void setKey(String key) {
        writeProperty("key", key);
    }

    public void setMemoryKey(String key) {
        this.key = key;
    }

    public void setMemoryUrl(String url) {
        this.url = url;
    }

    public String getUrl() {
        if (url == null) {
            url = getProperty("url");
            if (url == null) {
                System.out.println("Please set your server URL with the command '--set url {url}'");
                url = "http://localhost:8080/threadfix/rest";
                System.out.println("Using default of: " + url);
            }
        }

        return url;
    }

    public String getKey() {
        if (key == null) {
            key = getProperty("key");
            if (key == null) {
                System.err.println("Please set your API key with the command '--set key {key}'");
            }
        }

        return key;
    }

    private String getProperty(String propName) {
        if (properties == null) {
            readProperties();
            if (properties == null) {
                properties = new Properties();
                writeProperties();
            }
        }

        return properties.getProperty(propName);
    }

    private void writeProperty(String propName, String propValue) {
        readProperties();
        properties.setProperty(propName, propValue);
        writeProperties();
    }

    private void readProperties() {
        if (properties == null) {
            properties = new Properties();
        }

        FileInputStream in = null;
        File propertiesFile = new File("threadfix.properties");

        try {
            if (!propertiesFile.exists()) {
                propertiesFile.createNewFile();
            }

            in = new FileInputStream(propertiesFile);
            if (properties == null) {
                properties = new Properties();
            }
            properties.load(in);
        } catch (FileNotFoundException e) {
            try {
                System.out.println("Cannot find ThreadFix properties file: " + propertiesFile.getCanonicalPath());
            } catch(IOException ioe) {
                System.out.println("Cannot find ThreadFix properties file 'threadfix.properties' IOException encountered while trying.");
                ioe.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch(IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void writeProperties() {
        FileOutputStream out = null;
        try {
            out = new FileOutputStream("threadfix.properties");
            properties.store(out, "Writing.");
            out.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch(IOException e) {
                e.printStackTrace();
            }
        }
    }

}
