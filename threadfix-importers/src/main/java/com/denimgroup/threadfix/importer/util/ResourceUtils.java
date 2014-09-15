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

package com.denimgroup.threadfix.importer.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class ResourceUtils {

    protected static final SanitizedLogger log = new SanitizedLogger(ResourceUtils.class);

    private ResourceUtils(){}

    @Nullable
    public static InputStream getResourceAsStream(String fileName) {
        return ResourceUtils.class.getResourceAsStream(fileName);
    }

    public static URL getResourceAsUrl(String fileName) {
        return ResourceUtils.class.getClassLoader().getResource(fileName);
    }

    @Nonnull
    public static BufferedReader getResourceAsBufferedReader(String fileName) {
        try {
            return new BufferedReader(new FileReader(getResourceAsFile(fileName)));
        } catch (FileNotFoundException e) {
            throw new IllegalArgumentException("Invalid file passed to getResourceAsBufferedReader: " + fileName);
        }
    }

    @Nonnull
    public static File getResourceAsFile(String fileName) {
        URL url  = getResourceAsUrl(fileName);

        if (url != null) {
            URI fileString;
            try {
                fileString = url.toURI();
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("Invalid URL received from getResourceAsFile: " + url);
            }

            File file = new File(fileString);

            if (file.exists()) {
                return file;
            } else {
                throw new IllegalArgumentException("The file at " + fileString + " didn't exist.");
            }
        } else {
            throw new IllegalArgumentException("Got null URL for path " + fileName);
        }
    }

    @Nonnull
    public static Iterable<File> getFilesFromResourceFolder(String fileName) {
        List<File> fileList = list();

        File file = getResourceAsFile(fileName);

        assert file.exists();

        if (!file.isDirectory()) {
            throw new IllegalArgumentException("This method requires a valid resources folder as input.");
        }

        File[] files = file.listFiles();

        if (files != null && files.length > 0) {
            for (File childFile : files) {
                if (!childFile.getName().startsWith(".")) {
                    fileList.add(childFile);
                }
            }
        }

        return fileList;
    }


}
