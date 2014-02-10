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
