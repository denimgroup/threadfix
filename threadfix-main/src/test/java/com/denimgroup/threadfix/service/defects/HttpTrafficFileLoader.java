package com.denimgroup.threadfix.service.defects;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertFalse;

/**
 * Created by mac on 4/4/14.
 */
public class HttpTrafficFileLoader {

    public static String getResponse(String fileName) {
        try {
            String filePath = "httptraffic/" + fileName + ".txt";

            InputStream stream = HttpTrafficFileLoader.class.getClassLoader().getResourceAsStream(filePath);

            assertFalse("Stream was null for " + filePath, stream == null);

            return IOUtils.toString(stream);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

}
