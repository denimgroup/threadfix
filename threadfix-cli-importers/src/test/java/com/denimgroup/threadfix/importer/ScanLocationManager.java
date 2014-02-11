////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

        // let's make sure it ends with '/'.
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
            throw new IllegalStateException("The file " + rootFile.getAbsolutePath() + "didn't exist or wasn't a directory.");
        }

        return ROOT;
    }

}
