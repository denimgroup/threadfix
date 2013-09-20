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

import java.io.File;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

public class JSPMappings {
	
	private Map<String, Set<File>> includeMap = new HashMap<>();
	private Map<String, Map<Integer, List<String>>> parameterMap = new HashMap<>();
	private File rootFile = null;
	
	@SuppressWarnings("unchecked")
	public JSPMappings(File rootFile) {
		if (rootFile != null && rootFile.exists()) {

			this.rootFile = rootFile;
			Collection<File> jspFiles = FileUtils.listFiles(
					rootFile, JSPFileFilter.INSTANCE, TrueFileFilter.INSTANCE);
	
			for (File file : jspFiles) {
				Set<File> files = JSPIncludeParser.parse(file);
				if (files != null && !files.isEmpty()) {
					includeMap.put(FilePathUtils.getRelativePath(file, rootFile), files);
				}
			}
			
			for (File file : jspFiles) {
				Map<Integer, List<String>> parserResults = JSPParameterParser.parse(file);
				if (parserResults != null) {
					parameterMap.put(FilePathUtils.getRelativePath(file, rootFile), parserResults);
				}
			}
		}
	}
	
	public Set<File> getIncludedFiles(String relativePath) {
		return includeMap.get(relativePath);
	}
	
	public Map<Integer, List<String>> getParameterMap(String relativePath) {
		return parameterMap.get(relativePath);
	}
	
	// TODO simple optimizations to clean up the code and make it more efficient
	// create a map of parameter name to first line when this class is initialized and do lookups on that
	// it should be O(n) on the map and then O(1) instead of O(N) every time
	public Integer getFirstLineNumber(String relativeFilePath, String parameterName) {
		Map<Integer, List<String>> parameterMap = getParameterMap(relativeFilePath);
		
		Integer returnValue = Integer.MAX_VALUE;
		
		if (parameterMap != null && parameterName != null) {
			for (Integer integer : parameterMap.keySet()) {
				if (integer < returnValue &&
						parameterMap.get(integer) != null &&
						parameterMap.get(integer).contains(parameterName)) {
					returnValue = integer;
				}
			}
		}
		
		if (returnValue == Integer.MAX_VALUE) {
			returnValue = 1; // This way even if no parameter is found a marker can be created for the file
		}
		
		return returnValue;
	}
	
	public String getRelativePath(String dataFlowLocation) {
		return FilePathUtils.getRelativePath(dataFlowLocation, rootFile);
	}
}
