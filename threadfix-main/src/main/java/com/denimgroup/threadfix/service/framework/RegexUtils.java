package com.denimgroup.threadfix.service.framework;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexUtils {
	
	private RegexUtils(){}
	
	public static String getRegexResult(String targetString, String regex) {
		if (targetString == null || targetString.isEmpty() || regex == null || regex.isEmpty()) {
			return null;
		}

		Pattern pattern = Pattern.compile(regex);
		
		return getRegexResult(targetString, pattern);
	}
	
	/**
	 * For cases when it's better to store a pattern and skip compilation
	 * @param targetString
	 * @param pattern
	 * @return
	 */
	public static String getRegexResult(String targetString, Pattern pattern) {
		if (targetString == null || targetString.isEmpty() || pattern == null) {
			return null;
		}
		
		Matcher matcher = pattern.matcher(targetString);

		if (matcher.find())
			return matcher.group(1);
		else
			return null;
	}

}
