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
package com.denimgroup.threadfix;

import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.util.RawPropertiesHolder;

import java.io.File;
import java.io.IOException;

/**
 * Created by mcollins on 2/25/15.
 */
public class DiskUtils {

    private static final SanitizedLogger LOG = new SanitizedLogger(DiskUtils.class);

    private DiskUtils(){}

    public static String getRootPath() {
        String rootPath = System.getProperty("threadfix.scratchFolder");
        if (rootPath == null || rootPath.trim().equals("")) {
            rootPath = RawPropertiesHolder.getProperty("threadfix.scratchFolder");
        }
        return rootPath;
    }

    public static File getScratchFile(String path) {
        if (path == null) {
            throw new IllegalArgumentException("Null path passed to getScratchFile()");
        }

        LOG.debug("getScratchFile << " + path);

        final File returnFile;
        String root = getRootPath();

        if (root == null) {
            LOG.debug("Scratch folder is not configured, using relative path.");
            returnFile = new File(path);
        } else {
            File file = new File(root);

            if (!file.exists()) {
                LOG.error("Supplied scratch location (" + root + ") didn't exist. Defaulting to relative path.");
                returnFile = new File(path);
            } else if (!file.isDirectory()) {
                LOG.error("Supplied scratch location (" + root + ") is not a directory. Defaulting to relative path.");
                returnFile = new File(path);
            } else if (!file.canWrite()) {
                LOG.error("ThreadFix is unable to write to the supplied scratch location (" + root + "). Defaulting to relative path.");
                returnFile = new File(path);
            } else {
                LOG.debug("Got a valid scratch root from system properties.");
                String canonicalRoot = file.getAbsolutePath();

                boolean hasSlash = canonicalRoot.endsWith(File.separator) || path.startsWith(File.separator);
                if (hasSlash) {
                    returnFile = new File(canonicalRoot + path);
                } else {
                    returnFile = new File(canonicalRoot + File.separator + path);
                }
            }
        }

        LOG.debug("getScratchFile >> " + returnFile.getAbsolutePath());

        return returnFile;
    }

    public static long getAvailableDiskSpace() {

        File tmp = getScratchFile("tmp");
        try {
            if (!tmp.exists()) {
                tmp.createNewFile();
            }

            return tmp.getUsableSpace();
        } catch (IOException e) {
            throw new RestIOException(e, "Unable to store temporary file.");
        } finally {
            if (tmp.exists()) {
                boolean deletedTempFile = tmp.delete();
                if (!deletedTempFile) {
                    LOG.error("Unable to delete temporary file at " + tmp.getAbsolutePath());
                }
            }
        }
    }

    public static boolean isFileExists(String fullFilePath) {
        File f = new File(fullFilePath);
        return f.exists() && !f.isDirectory();
    }
}
