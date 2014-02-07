package com.denimgroup.threadfix.importer.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by mac on 2/4/14.
 */
public class RegexUtils {

    private static final SanitizedLogger LOG = new SanitizedLogger(RegexUtils.class);

    /**
     * Utility to prevent declaring a bunch of Matchers and Patterns.
     *
     * @param targetString
     * @param regex
     * @return result of applying Regex
     */
    public static String getRegexResult(String targetString, String regex) {
        if (targetString == null || targetString.isEmpty() || regex == null || regex.isEmpty()) {
            LOG.warn("getRegexResult got null or empty input.");
            return null;
        }

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(targetString);

        if (matcher.find()) {
            return matcher.group(1);
        } else {
            return null;
        }
    }

}
