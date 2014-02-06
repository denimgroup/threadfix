package com.denimgroup.threadfix.importer;

import java.io.File;

/**
 * Created by mac on 2/6/14.
 */
public class ScanLocationManager {

    private static final String root = getRootInternal();

    private static String getRootInternal() {
        return "/Users/mac/Documents/Git/threadfix/" +
                "threadfix-main/src/test/resources/SupportingFiles/";//System.getProperty("SCAN_FILE_LOCATION");
    }

    public static String getRoot() {

        if (root == null) {
            throw new IllegalStateException("We need the scan files to do the tests.");
        }

        File rootFile = new File(root);
        if (!rootFile.exists() || !rootFile.isDirectory()) {
            throw new IllegalStateException("The file didn't exist or wasn't a directory.");
        }

        return root;
    }

}
