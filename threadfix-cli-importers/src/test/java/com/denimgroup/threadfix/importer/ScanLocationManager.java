package com.denimgroup.threadfix.importer;

import java.io.File;

/**
 * Created by mac on 2/6/14.
 */
public class ScanLocationManager {

    private static final String
            ERROR_MESSAGE = "We need the scan files to do the tests. Please set the system variable SCAN_FILE_LOCATION",
            ROOT = getRootInternal();

    private static String getRootInternal() {
        String root =  "/Users/mcollins/documents/git/threadfix/threadfix-main/src/test/resources/SupportingFiles/";//System.getProperty("SCAN_FILE_LOCATION");

        if (root == null) {
            throw new IllegalStateException(ERROR_MESSAGE);
        }

        // let's make sure it ends with /.
        if (!root.endsWith("/")) {
            root = root + "/";
        }

        return root;
    }

    public static String getRoot() {

        if (ROOT == null) {
            throw new IllegalStateException(ERROR_MESSAGE);
        }

        File rootFile = new File(ROOT);
        if (!rootFile.exists() || !rootFile.isDirectory()) {
            throw new IllegalStateException("The file didn't exist or wasn't a directory.");
        }

        return ROOT;
    }

}
