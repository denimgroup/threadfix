////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.plugins.intellij.rest;

import com.denimgroup.threadfix.plugins.intellij.rest.RestUtils;

import java.util.HashMap;
import java.util.Map;

public class ThreadFixApplicationService {

	public static Map<String, String> getApplications() {
		String csvString = getApplicationCSV();
		
		Map<String, String> map = new HashMap<String, String>();
		
		String[] lines = csvString.split("\n");
		
		for (String line : lines) {
			String[] components = line.split(",");
			if (components.length == 2) {
				map.put(components[0], components[1]);
			}
		}
		
		return map;
	}
	
	private static String getApplicationCSV() {
		return RestUtils.getFromSettings().getApplications();
	}

}
