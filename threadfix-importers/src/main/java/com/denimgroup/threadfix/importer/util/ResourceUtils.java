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

package com.denimgroup.threadfix.importer.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import static com.denimgroup.threadfix.CollectionUtils.set;

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
        InputStream resourceAsStream = getResourceAsStream(fileName);

        if (resourceAsStream == null) {
            throw new IllegalArgumentException("Invalid argument (" + fileName +
                    ") encountered: getResourceAsStream returned null.");
        }

        return new BufferedReader(new InputStreamReader(resourceAsStream));
    }

    /**
     * This name is long on purpose because it does a very specific thing
     * @param directoryName
     * @return
     */
    @Nonnull
    public static <T> Iterable<String> getFileNamesInResourceDirectoryFromJarWithClass(Class<T> jarClass, String directoryName) {
        try {
            return getResourceListing(jarClass, directoryName);
        } catch (URISyntaxException e) {
            throw new IllegalStateException("Scanner plugin configuration was invalid. Please modify and try again.", e);
        } catch (IOException e) {
            throw new IllegalStateException("Scanner plugin configuration was invalid. Please modify and try again.", e);
        }
    }

    /**
     * List directory contents for a resource folder. Not recursive.
     * This is basically a brute-force implementation.
     * Works for regular files and also JARs.
     *
     * @param clazz Any java class that lives in the same place as the resources you want.
     * @param path Should end with "/", but not start with one.
     * @return Just the name of each member item, not the full paths.
     * @throws URISyntaxException
     * @throws IOException
     */
    private static Set<String> getResourceListing(Class clazz, String path) throws URISyntaxException, IOException {
        URL dirURL = clazz.getClassLoader().getResource(path);
        if (dirURL != null && dirURL.getProtocol().equals("file")) {
        /* A file path: easy enough */
            String[] fileList = new File(dirURL.toURI()).list();
            Set<String> strings = set();

            for (String string : fileList) {
                strings.add(path + "/" + string);
            }

            return strings;
        }

        if (dirURL == null) {
        /*
         * In case of a jar file, we can't actually find a directory.
         * Have to assume the same jar as clazz.
         */
            String me = clazz.getName().replace(".", "/") + ".class";
            dirURL = clazz.getClassLoader().getResource(me);
        }

        if (dirURL != null && dirURL.getProtocol().equals("jar")) {
            /* A JAR path */
            String jarPath = dirURL.getPath().substring(5, dirURL.getPath().indexOf("!")); //strip out only the JAR file
            JarFile jar = new JarFile(URLDecoder.decode(jarPath, "UTF-8"));
            Enumeration<JarEntry> entries = jar.entries(); //gives ALL entries in jar
            Set<String> result = set(); //avoid duplicates in case it is a subdirectory
            while(entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (name.startsWith(path) && !name.endsWith("/")) { //filter according to the path
                    result.add(name);
                }
            }
            return result;
        }

        throw new UnsupportedOperationException("Cannot list files for URL "+dirURL);
    }


}
