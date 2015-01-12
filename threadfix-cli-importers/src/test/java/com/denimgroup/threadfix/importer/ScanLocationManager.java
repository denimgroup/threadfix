////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

package com.denimgroup.threadfix.importer;

import java.io.File;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class ScanLocationManager {

    private static final String
            PROPERTY_NAME = "SCAN_FILE_LOCATION",
            ERROR_MESSAGE = "We need the scan files to do the tests. Please set the system variable " + PROPERTY_NAME,
            ROOT = getRootInternal();

    private static String getRootInternal() {
        check();
        String root = System.getProperty(PROPERTY_NAME);

        if (root == null) {
            throw new IllegalStateException(ERROR_MESSAGE);
        }

        // let's make sure it ends with '/'.
        if (!root.endsWith("/")) {
            root = root + "/";
        }

        return root;
    }

    public static String getRoot() {
        check();

        File rootFile = new File(ROOT);
        if (!rootFile.exists() || !rootFile.isDirectory()) {
            throw new IllegalStateException("The file " + rootFile.getAbsolutePath() + "didn't exist or wasn't a directory.");
        }

        return ROOT;
    }

    private static void check() {
        if (System.getProperty(PROPERTY_NAME) == null) {
            throw new IllegalStateException(ERROR_MESSAGE);
        }
    }

    public static Collection<String> getFilesInDirectory(String extension) {
        check();
        File directory = new File(getRoot() + extension);

        if (!directory.exists() && directory.isDirectory()) {
            throw new IllegalStateException("Tried to add an invalid file: " + directory.getAbsolutePath());
        }

        File[] files = directory.listFiles();

        Set<String> returnFiles = new HashSet<>();

        if (files == null) {
            throw new IllegalStateException("File.listFiles() returned null for " + directory.getAbsolutePath() + ".");
        }

        for (File file : files) {
            if (file.isFile() && !file.getName().startsWith(".")) {
                returnFiles.add(file.getAbsolutePath());
            }
        }

        if (returnFiles.isEmpty()) {
            throw new IllegalStateException("No scan files found in " + directory.getAbsolutePath());
        }

        return returnFiles;
    }

}
