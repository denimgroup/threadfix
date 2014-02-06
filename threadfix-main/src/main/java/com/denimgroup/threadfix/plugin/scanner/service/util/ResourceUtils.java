package com.denimgroup.threadfix.plugin.scanner.service.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;

public class ResourceUtils {

    protected static final SanitizedLogger log = new SanitizedLogger(ResourceUtils.class);

    private ResourceUtils(){}

    /**
     * Loads a file from src/main/resources
     * @param fileName the file name
     * @return the File or null if an error occurs or it cannot be found
     */
    public static File getResource(String fileName) {

        File returnFile = null;

        try {
            URL fileUrl = getUrl(fileName);
            if (fileUrl != null) {
                returnFile = new File(fileUrl.toURI());
            }
        } catch (URISyntaxException e) {
            log.warn("Unable to load file due to URISyntaxException.", e);
        }

        return returnFile;
    }

    public static URL getUrl(String fileName) {
        return ResourceUtils.class.getClassLoader().getResource(fileName);
    }

}
