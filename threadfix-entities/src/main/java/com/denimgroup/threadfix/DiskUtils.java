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
package com.denimgroup.threadfix;

import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.io.File;
import java.io.IOException;

/**
 * Created by mcollins on 2/25/15.
 */
public class DiskUtils {

    private static final SanitizedLogger LOG = new SanitizedLogger(DiskUtils.class);

    private DiskUtils(){}

    public static long getAvailableDiskSpace() {

        File tmp = new File("tmp");
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
}
