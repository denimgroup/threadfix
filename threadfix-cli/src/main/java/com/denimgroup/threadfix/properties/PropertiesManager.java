////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.properties;


import java.io.*;
import java.util.Properties;

public class PropertiesManager {

    private String url = null;
    private String key = null;
    private Properties properties;

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
        try  {
            out = new FileOutputStream("threadfix.properties");
            properties.store(out, "Writing.");
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }

}
