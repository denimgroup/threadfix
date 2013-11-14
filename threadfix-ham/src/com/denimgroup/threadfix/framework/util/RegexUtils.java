package com.denimgroup.threadfix.framework.util;

import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexUtils {
	
	private RegexUtils(){}
	
	@Nullable
    public static String getRegexResult(@Nullable String targetString, @Nullable String regex) {
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
	@Nullable
    public static String getRegexResult(@Nullable String targetString, @Nullable Pattern pattern) {
		if (targetString == null || targetString.isEmpty() || pattern == null) {
			return null;
		}
		
		Matcher matcher = pattern.matcher(targetString);

		if (matcher.find())
			return matcher.group(1);
		else
			return null;
	}
	
	/**
	 * For cases when it's better to store a pattern and skip compilation
	 * @param targetString
	 * @param pattern
	 * @return
	 */
	@Nullable
    public static List<String> getRegexResults(@Nullable String targetString, @Nullable Pattern pattern) {
		if (targetString == null || targetString.isEmpty() || pattern == null) {
			return null;
		}
		
		Matcher matcher = pattern.matcher(targetString);

		List<String> resultsList = new ArrayList<>(matcher.groupCount());
		
		while (matcher.find()) {
			resultsList.add(matcher.group());
		}
		
		return resultsList;
	}

}
