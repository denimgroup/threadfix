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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// TODO make more error resistant
public class ProjectDirectory {
	
	private File directory;
	
	// TODO investigate building a Map<String, Set<File>> to enable much easier file lookup
	// this may be a good performance gain if enough files are in the project
	public ProjectDirectory(File directory) {
		this.directory = directory;
	}
	
	public String getDirectoryPath() {
		return directory.getAbsolutePath();
	}
	
	// TODO we may be able to get better results with some more advanced logic here
	// maybe skip directories like "test", look in specific paths or at least check guesses
	// on the other hand I don't really see this being a bottleneck
	public File findWebXML() {
		return findFile("web.xml", "WEB-INF");
	}
	
	public File findFile(String name, String... probableDirectoryNames) {
		if (probableDirectoryNames == null || probableDirectoryNames.length == 0) {
			return findFileRecursive(name, directory, new ArrayList<String>());
		} else {
			return findFileRecursive(name, directory, Arrays.asList(probableDirectoryNames));
		}
	}
	
	private File findFileRecursive(String name, File currentDirectory, List<String> probableDirectoryNames) {
		if (currentDirectory == null || !currentDirectory.exists()) {
			return null;
		}
		
    	List<File> directories = new ArrayList<>();
    	for (File file : currentDirectory.listFiles()) {
    		
    		if (file.isDirectory() && probableDirectoryNames.contains(file.getName())) {
    			return findFileRecursive(name, file, probableDirectoryNames);
    		} else if (file.isFile() && file.getName().equals(name)) {
    			return file;
    		} else if (file.isDirectory()) {
    			directories.add(file);
    		}
    	}
    	
    	for (File directory : directories) {
    		File maybeTargetFile = findFileRecursive(name, directory, probableDirectoryNames);
    		if (maybeTargetFile != null) {
    			return maybeTargetFile;
    		}
    	}
    	
    	return null;
	}

}
