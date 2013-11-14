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
package com.denimgroup.threadfix.framework.impl.spring;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import com.denimgroup.threadfix.framework.engine.AbstractEndpoint;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class SpringControllerEndpoint extends AbstractEndpoint {
	
	public static final String GENERIC_INT_SEGMENT = "{id}";
	private static final String requestMappingStart = "RequestMethod.";
	
	@NotNull
    private final String rawFilePath, rawUrlPath;
	@NotNull
    private final Set<String> methods, parameters;
	private final int startLineNumber, endLineNumber;
	
	@Nullable
    private String cleanedFilePath = null, cleanedUrlPath = null;
	
	private String fileRoot;
	
	public SpringControllerEndpoint(@NotNull String filePath, @NotNull String urlPath,
            @NotNull Collection<String> methods, @NotNull Collection<String> parameters,
			int startLineNumber, int endLineNumber) {
		this.rawFilePath     = filePath;
		this.rawUrlPath      = urlPath;
		this.startLineNumber = startLineNumber;
		this.endLineNumber   = endLineNumber;
		
		this.parameters = new HashSet<>(parameters);
		this.methods    = getCleanedSet(methods);
	}

    @NotNull
	private Set<String> getCleanedSet(@NotNull Collection<String> methods) {
		Set<String> returnSet = new HashSet<>();
		for (String method : methods) {
			if (method.startsWith(requestMappingStart)) {
				returnSet.add(method.substring(requestMappingStart.length()));
			} else {
				returnSet.add(method);
			}
		}
		
		if (returnSet.isEmpty()) {
			returnSet.add("GET");
		}
		
		return returnSet;
	}
	
	@NotNull
    @Override
	public Set<String> getParameters() {
		return parameters;
	}

    @NotNull
    public String getCleanedFilePath() {
		if (cleanedFilePath == null && fileRoot != null &&
				rawFilePath.contains(fileRoot)) {
			cleanedFilePath = rawFilePath.substring(fileRoot.length());
		}

        if (cleanedFilePath == null) {
            return rawFilePath;
        }
		
		return cleanedFilePath;
	}
	
	public void setFileRoot(String fileRoot) {
		this.fileRoot = fileRoot;
	}

	@Nullable
    public String getCleanedUrlPath() {
		if (cleanedUrlPath == null) {
			cleanedUrlPath = cleanUrlPathStatic(rawUrlPath);
		}
		
		return cleanedUrlPath;
	}
	
	@Nullable
    public static String cleanUrlPathStatic(@Nullable String rawUrlPath) {
		if (rawUrlPath == null) {
			return null;
		} else {
			return rawUrlPath
					.replaceAll("/\\*/", "/" + GENERIC_INT_SEGMENT + "/")
					.replaceAll("\\{[^\\}]+\\}", GENERIC_INT_SEGMENT);
		}
	}
	
	@Override
	public boolean matchesLineNumber(int lineNumber) {
		return lineNumber < endLineNumber && lineNumber > startLineNumber;
	}
	
	@NotNull
    @Override
	public String toString() {
		return "[" + getCleanedFilePath() +
				":" + startLineNumber +
				"-" + endLineNumber +
				" -> " + getHttpMethods() +
				" " + getCleanedUrlPath() +
				" " + getParameters() +
				"]";
	}

	@NotNull
    @Override
	public Set<String> getHttpMethods() {
		return methods;
	}

	@NotNull
    @Override
	public String getUrlPath() {
		String path = getCleanedUrlPath();
        if (path != null) {
            return path;
        } else {
            return "";
        }
	}

	@NotNull
    @Override
	public String getFilePath() {
		return getCleanedFilePath();
	}

	@Override
	public int getStartingLineNumber() {
		return startLineNumber;
	}

	@Override
	public int getLineNumberForParameter(String parameter) {
		return startLineNumber;
	}
}
