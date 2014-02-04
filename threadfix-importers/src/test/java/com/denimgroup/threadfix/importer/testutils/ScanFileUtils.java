package com.denimgroup.threadfix.importer.testutils;

import java.io.File;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by mac on 2/4/14.
 */
public class ScanFileUtils {

    private static void check() {
        if (System.getProperty("SCAN_FILE_LOCATION") == null) {
            throw new IllegalStateException("We need the scan files to do the tests.");
        }
    }

    public static String getFile(String extension) {
        check();
        return System.getProperty("SCAN_FILE_LOCATION") + extension;
    }

    public static Collection<String> getFilesInDirectory(String extension) {
        check();
        File directory = new File(System.getProperty("SCAN_FILE_LOCATION") + extension);

        if (!directory.exists() && directory.isDirectory()) {
            throw new IllegalStateException("Tried to add an invalid file: " + directory.getAbsolutePath());
        }

        File[] files = directory.listFiles();

        Set<String> returnFiles = new HashSet<>();

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
