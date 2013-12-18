package com.denimgroup.threadfix.service.util;

import com.denimgroup.threadfix.service.SanitizedLogger;

/**
 * Created by mac on 12/18/13.
 */
public class IntegerUtils {

    private static final SanitizedLogger log = new SanitizedLogger(IntegerUtils.class);

    private IntegerUtils(){}

    /**
     * Returns Integer.valueOf(input) with exception handling. Will return -1 if it fails to parse.
     *
     * @param input String representation of an integer
     * @return the parsed number, or -1 on failure
     */
    public static int getPrimitive(String input) {
        try {
            return Integer.valueOf(input);
        } catch (NumberFormatException e) {
            log.warn("Non-numeric input encountered: " + input, e);
            return -1;
        }
    }

    /**
     * Returns Integer.valueOf(input) with exception handling. Will return null if it fails to parse.
     *
     * @param input String representation of an integer
     * @return the parsed number, or null on failure
     */
    public static Integer getIntegerOrNull(String input) {
        try {
            return Integer.valueOf(input);
        } catch (NumberFormatException e) {
            log.warn("Non-numeric input encountered: " + input, e);
            return null;
        }
    }
}
