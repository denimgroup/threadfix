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
package com.denimgroup.threadfix.service.framework;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SpringControllerEndpoint {
	
	public static final String GENERIC_INT_SEGMENT = "{id}";
	private static final String requestMappingStart = "RequestMethod.";
	
	private final String rawFilePath, rawUrlPath;
	private final Set<String> methods;
	private final int startLineNumber, endLineNumber;
	
	private String cleanedFilePath = null, cleanedUrlPath = null;
	
	private String fileRoot;
	
	public SpringControllerEndpoint(String filePath, String urlPath, List<String> methods,
			int startLineNumber, int endLineNumber) {
		this.rawFilePath = filePath;
		this.rawUrlPath = urlPath;
		this.startLineNumber = startLineNumber;
		this.endLineNumber = endLineNumber;
		
		this.methods = getCleanedSet(methods);
	}
	
	private Set<String> getCleanedSet(List<String> methods) {
		Set<String> returnSet = new HashSet<>();
		for (String method : methods) {
			if (method.startsWith(requestMappingStart)) {
				returnSet.add(method.substring(requestMappingStart.length()));
			} else {
				returnSet.add(method);
			}
		}
		return returnSet;
	}
	
	public String getRawFilePath() {
		return rawFilePath;
	}

	public String getRawUrlPath() {
		return rawUrlPath;
	}

	public String getCleanedFilePath() {
		if (cleanedFilePath == null && fileRoot != null && 
				rawFilePath != null && rawFilePath.contains(fileRoot)) {
			cleanedFilePath = rawFilePath.substring(fileRoot.length());
		}
		
		return cleanedFilePath;
	}
	
	public void setFileRoot(String fileRoot) {
		this.fileRoot = fileRoot;
	}

	public String getCleanedUrlPath() {
		if (cleanedUrlPath == null) {
			cleanedUrlPath = cleanUrlPathStatic(rawUrlPath);
		}
		
		return cleanedUrlPath;
	}
	
	public static String cleanUrlPathStatic(String rawUrlPath) {
		if (rawUrlPath == null) {
			return null;
		} else {
			return rawUrlPath
					.replaceAll("/\\*/", "/" + GENERIC_INT_SEGMENT + "/")
					.replaceAll("\\{[^\\}]+\\}", GENERIC_INT_SEGMENT);
		}
	}
	
	public static String cleanUrlPathDynamic(String rawUrlPath) {
		if (rawUrlPath == null) {
			return null;
		} else {
			return rawUrlPath
					.replaceAll("/[0-9]+/", "/" + GENERIC_INT_SEGMENT + "/")
					.replaceAll("\\.html", "")
					.replaceAll("/[0-9]+$", "/" + GENERIC_INT_SEGMENT);
		}
	}
	
	public boolean matchesLineNumber(int lineNumber) {
		return lineNumber < endLineNumber && lineNumber > startLineNumber;
	}
	
	public boolean matchesMethod(String method) {
		return method != null && methods != null && methods.contains(method.toUpperCase());
	}

	@Override
	public String toString() {
		return "[" + getCleanedFilePath() + 
				":" + startLineNumber + 
				"-" + endLineNumber + 
				" -> " + getMethod() + 
				" " + getCleanedUrlPath() + 
				"]"; 
	}

	public Set<String> getMethod() {
		return methods;
	}
	
}
