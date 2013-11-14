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
package com.denimgroup.threadfix.framework.util;

import org.jetbrains.annotations.Nullable;

import java.io.File;

public class FilePathUtils {

	private FilePathUtils(){}
	
	@Nullable
    public static String getRelativePath(@Nullable File projectFile, @Nullable File rootFile) {
		String returnPath = null;
		
		if (projectFile != null && rootFile != null) {
			returnPath = getRelativePath(projectFile.getAbsolutePath(), rootFile.getAbsolutePath());
		}
		
		return returnPath;
	}
	
	@Nullable
    public static String getRelativePath(@Nullable String projectFileString, @Nullable File projectRootFile) {
		String returnPath = null;
		
		if (projectFileString != null && projectRootFile != null) {
			returnPath = getRelativePath(projectFileString, projectRootFile.getAbsolutePath());
		}
		
		return returnPath;
	}
	
	@Nullable
    public static String getRelativePath(@Nullable File projectFile, @Nullable String projectRoot) {
		String returnPath = null;
		
		if (projectFile != null && projectRoot != null) {
			returnPath = getRelativePath(projectFile.getAbsolutePath(), projectRoot);
		}
		
		return returnPath;
	}
	
	@Nullable
    public static String getRelativePath(@Nullable String string, @Nullable String projectRoot) {
		String returnPath = null;
		
		if (string != null && projectRoot != null && 
				string.startsWith(projectRoot)) {
			returnPath = string
					.substring(projectRoot.length())
					.replace('\\', '/');
		}
		
		return returnPath;
	}
	
}
