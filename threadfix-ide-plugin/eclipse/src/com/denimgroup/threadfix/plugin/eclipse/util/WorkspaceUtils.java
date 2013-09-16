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
package com.denimgroup.threadfix.plugin.eclipse.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.core.resources.IContainer;
import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IFolder;
import org.eclipse.core.resources.IMarker;
import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.ui.texteditor.MarkerUtilities;


public class WorkspaceUtils {
	
	public static final String
		PROBLEM_TYPE = "com.denimgroup.threadfix.plugin.eclipse.threadfixmarker",
		ECLIPSE_PROBLEM_TYPE = "org.eclipse.core.resources.problemmarker";
	
	private WorkspaceUtils() {}
	
	public static List<IFile> getAllFiles() {
		List<IFile> fileMap = new ArrayList<>();
		
		try {
			IProject[] projects = ResourcesPlugin.getWorkspace().getRoot().getProjects();
			
			for (IProject project : projects) {
				addChildrenRecursive(project, fileMap);
			}
		} catch (CoreException e) {
			e.printStackTrace();
		}
		
		return fileMap;
	}
	
	private static void addChildrenRecursive(IContainer container, List<IFile> resources) throws CoreException {
		if (container != null && container.members() != null) {
			for (IResource resource : container.members()) {
				if (resource instanceof IFolder) {
					addChildrenRecursive((IFolder) resource, resources);
				} else if (resource instanceof IFile){
					resources.add((IFile) resource);
				}
			}
		}
	}
	
	public static Map<String, Set<IFile>> getFileMap() {
		Map<String, Set<IFile>> fileMap = new HashMap<>();
		
		for (IFile file : getAllFiles()) {
			if (fileMap.get(file.getName()) == null) {
				fileMap.put(file.getName(), new HashSet<IFile>());
			}
			fileMap.get(file.getName()).add(file);
		}
		
		return fileMap;
	}
	
	public static void createMarker(IResource resource, VulnerabilityMarker marker) throws CoreException {
		Map<String, Object> attribs = new HashMap<>();
		
	    attribs.put(IMarker.SEVERITY, new Integer(IMarker.SEVERITY_ERROR));
	    attribs.put(IMarker.LINE_NUMBER, marker.lineNumber);
	    attribs.put(IMarker.MESSAGE, marker.toString());
	    
	    MarkerUtilities.createMarker(resource, attribs, ECLIPSE_PROBLEM_TYPE);
	}
	
	public static void clearMarkers(IResource resource) throws CoreException {
		for (IMarker marker : getMarkers(resource)) {
			marker.delete();
		}
	}
	
	public static IMarker[] getMarkers(IResource target) throws CoreException {
	    return target.findMarkers(ECLIPSE_PROBLEM_TYPE, true, IResource.DEPTH_INFINITE);
	}

}
