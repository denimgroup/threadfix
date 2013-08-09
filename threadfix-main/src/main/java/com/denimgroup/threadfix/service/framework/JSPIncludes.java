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
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

public class JSPIncludes {
	
	Map<String, Set<File>> includeMap = new HashMap<>();
	Map<String, JSPParameterParser> parameterMap = new HashMap<>();
	
	@SuppressWarnings("unchecked")
	public JSPIncludes(File rootFile) {
		Collection<File> jspFiles = FileUtils.listFiles(
				rootFile, JSPFileFilter.INSTANCE, TrueFileFilter.INSTANCE);

		for (File file : jspFiles) {
			Set<File> files = JSPIncludeParser.parse(file);
			if (files != null && !files.isEmpty()) {
				includeMap.put(FilePathUtils.getRelativePath(file, rootFile), files);
			}
		}
		
		for (File file : jspFiles) {
			JSPParameterParser parser = JSPParameterParser.parse(file);
			if (parser != null) {
				parameterMap.put(FilePathUtils.getRelativePath(file, rootFile), parser);
			}
		}
	}
	
	public Set<File> getIncludedFiles(String relativePath) {
		return includeMap.get(relativePath);
	}
}
