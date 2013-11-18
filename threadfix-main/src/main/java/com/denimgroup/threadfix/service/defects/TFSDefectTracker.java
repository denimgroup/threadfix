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
package com.denimgroup.threadfix.service.defects;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.microsoft.tfs.core.TFSTeamProjectCollection;
import com.microsoft.tfs.core.clients.workitem.WorkItem;
import com.microsoft.tfs.core.clients.workitem.WorkItemClient;
import com.microsoft.tfs.core.clients.workitem.fields.FieldDefinitionCollection;
import com.microsoft.tfs.core.clients.workitem.project.Project;
import com.microsoft.tfs.core.clients.workitem.project.ProjectCollection;
import com.microsoft.tfs.core.clients.workitem.query.WorkItemCollection;
import com.microsoft.tfs.core.exceptions.TECoreException;
import com.microsoft.tfs.core.exceptions.TFSUnauthorizedException;
import com.microsoft.tfs.core.httpclient.Credentials;
import com.microsoft.tfs.core.httpclient.UsernamePasswordCredentials;
import com.microsoft.tfs.core.ws.runtime.exceptions.UnauthorizedException;

public class TFSDefectTracker extends AbstractDefectTracker {

	protected static final SanitizedLogger staticLog = new SanitizedLogger("TFSDefectTracker");

	// We need to load the native libraries and this seems to be the best spot.
	// The idea is to use the same code for loading all the libraries but use
	// string values to specify which folder they are in and which names to look up.
	static {
		String osName = System.getProperty("os.name"), osArch = System.getProperty("os.arch");
		staticLog.info("Attempting to load libraries for " + osName + ".");

		String folderName = null, prefix = null, suffix = null;
		String[] names = null;

		if (osName == null) {
			staticLog.error("Received null from System.getProperty(\"os.name\"), " +
					"something is wrong here.");
		} else if (osName.startsWith("Windows")) {
			folderName = "/tfs-native/win32/x86";
			if (osArch != null && osArch.contains("64")) {
				folderName += "_64";
			}
			prefix = "native_";
			suffix = ".dll";
			names = new String[] { "synchronization", "auth", "console",
					"filesystem", "messagewindow", "misc", "registry" };

		} else if (osName.startsWith("Mac OS")) {
			folderName = "/tfs-native/macosx";
			prefix = "libnative_";
			suffix = ".jnilib";
			names = new String[] { "auth", "console", "filesystem", "keychain",
					"misc", "synchronization" };
		} else if (osName.startsWith("Linux")) {
			String archExtension = osArch;
			if (osArch.equals("amd64")) {
				archExtension = "x86_64";
			} else if (osArch.equals("i386")) {
				archExtension = "x86";
			}

			folderName = "/tfs-native/linux/" + archExtension;
			prefix = "libnative_";
			suffix = ".so";
			names = new String[] { "auth", "console", "filesystem", "misc",
					"synchronization" };

		} else if (osName.equals("hpux") || osName.equals("aix")
				|| osName.equals("solaris")) {
			folderName = "/tfs-native/" + osName + "/";
			prefix = "libnative_";
			suffix = ".so";
			if (osArch != null && osArch.equals("PA_RISC")) {
				suffix = ".sl";
			} else if (osArch != null && osArch.equals("ppc")) {
				suffix = ".a";
			}
		} else {
			staticLog.error("OS name not supported by TFS. " +
					"The TFS integration will fail.");
		}

		if (folderName != null && names != null) {
			try {

                URL url = TFSDefectTracker.class.getClassLoader()
                        .getResource(folderName);

                if (url != null) {
                    String base = url.toURI().getPath()
                            .replaceFirst("file:", "");
                    try {
                        for (String library : names) {
                            System.load(base + prefix + library + suffix);
                        }

                        staticLog.info("Successfully loaded native libraries for "
                                + osName + ".");
                    } catch (UnsatisfiedLinkError e) {
                        staticLog.error("Unable to locate one of the libraries.", e);
                    }
                }
			} catch (URISyntaxException e) {
				staticLog.error("Unable to convert the path String to a URI.", e);
			}								

		} else {
			staticLog.error("Attempt to load TFS native libraries failed..");
		}
	}

	public TFSDefectTracker() {
	}

	private WorkItemClient getClient() {
		Credentials credentials = new UsernamePasswordCredentials(
				getUsername(), getPassword());

		URI uri = null;
		try {
			uri = new URI(getUrl());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}

		TFSTeamProjectCollection projects = new TFSTeamProjectCollection(uri, credentials);
		try {
			return projects.getWorkItemClient();
		} catch (UnauthorizedException | TFSUnauthorizedException e) {
			log.warn("TFSUnauthorizedException encountered, unable to connect to TFS. " +
					"Check credentials and endpoint.");
		}
		
		return null;
	}

	@Override
	public String createDefect(List<Vulnerability> vulnerabilities,
			DefectMetadata metadata) {
		WorkItemClient workItemClient = getClient();
		
		if (workItemClient == null) {
			log.warn("Unable to create defect.");
			return null;
		}
		Project project;
		
		try {
			project = workItemClient.getProjects().get(getProjectName());
		} catch (UnauthorizedException | TFSUnauthorizedException e) {
			log.warn("Ran into TFSUnauthorizedException while trying to retrieve products.");
			workItemClient.close();
			return null;
		}
		
		if (project == null) {
			log.warn("Product was not found. Unable to create defect.");
			return null;
		}
		
		WorkItem item = workItemClient.newWorkItem(project
				.getVisibleWorkItemTypes()[0]);

		if (item == null) {
			log.warn("Unable to create item in TFS.");
			return null;
		}
		
		item.setTitle(metadata.getDescription());
		item.getFields().getField("Description")
				.setValue(makeDescription(vulnerabilities, metadata));
		item.getFields().getField("Priority").setValue(metadata.getPriority());

		item.save();
		
		String itemId = String.valueOf(item.getID());

		workItemClient.close();
		
		return itemId;
	}

	@Override
	public String getBugURL(String endpointURL, String bugID) {
		return null;
	}

	@Override
	public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {
		Map<Defect, Boolean> returnMap = new HashMap<>();
		Map<String, String> stringStatusMap = new HashMap<>();
		Map<String, Boolean> openStatusMap = new HashMap<>();

		WorkItemClient workItemClient = getClient();
		
		if (workItemClient == null) {
			log.warn("Updating bug status failed.");
			return null;
		}

		StringBuilder builder = new StringBuilder();
		for (Defect defect : defectList) {
			builder.append(defect.getNativeId()).append(",");
		}

		String ids = builder.substring(0, builder.length() - 1);
		String wiqlQuery = "Select ID, State from WorkItems where (id in ("
				+ ids + "))";

		// Run the query and get the results.
		WorkItemCollection workItems = workItemClient.query(wiqlQuery);

		for (int i = 0; i < workItems.size(); i++) {
			WorkItem workItem = workItems.getWorkItem(i);

			stringStatusMap.put(String.valueOf(workItem.getID()),
					(String) workItem.getFields().getField("State")
							.getOriginalValue());
			openStatusMap.put(String.valueOf(workItem.getID()),
					workItem.isOpen());
		}

		log.info("Updating bug statuses.");

		// Find the open or closed status for each defect.
		for (Defect defect : defectList) {
			if (defect != null) {
				returnMap.put(defect, openStatusMap.get(defect.getNativeId()));
				defect.setStatus(stringStatusMap.get(defect.getNativeId()));
			}
		}
		
		workItemClient.close();

		return returnMap;
	}

	@Override
	public String getProductNames() {
		log.info("Getting list of product names.");
		WorkItemClient workItemClient = getClient();
		
		if (workItemClient == null) {
			log.warn("Unable to retrieve WorkItemClient, returning an unauthorized message.");
			setLastError("Invalid username / password combination");
			return null;
		}

		ProjectCollection collection = null;

        try {
            collection = workItemClient.getProjects();
        } catch (UnauthorizedException | TFSUnauthorizedException e) {
            log.warn("Ran into TFSUnauthorizedException while trying to retrieve products.");
            setLastError("Invalid username / password combination");
            return null;
        } finally {
            workItemClient.close();
        }

		if (collection == null || collection.size() == 0) {
			log.warn("Collection of projects was null or empty.");
			return null;
		}

		StringBuilder builder = new StringBuilder();

		for (Project project : collection) {
			builder.append(project.getName()).append(",");
		}

		return builder.subSequence(0, builder.length() - 2).toString();
	}

	@Override
	public String getProjectIdByName() {
		WorkItemClient workItemClient = getClient();
		
		if (workItemClient == null) {
			log.warn("Unable to connect to TFS to retrieve project name.");
			return null;
		}

		Project project = null;
		try {
			project = workItemClient.getProjects().get(getProjectName());
		} catch (UnauthorizedException | TFSUnauthorizedException e) {
			log.warn("Ran into TFSUnauthorizedException while trying to retrieve products.");
			return null;
		} finally {
			workItemClient.close();
		}
		
		if (project == null) {
			return null;
		} else {
			return String.valueOf(project.getID());
		}
	}

	@Override
	public ProjectMetadata getProjectMetadata() {
		log.info("Collecting project metadata");

		List<String> statuses = new ArrayList<>();
		List<String> priorities = new ArrayList<>();
		List<String> emptyList = new ArrayList<>();
		emptyList.add("-");

		statuses.add("New");

		WorkItemClient workItemClient = getClient();
		if (workItemClient == null) {
			log.warn("Unable to connect to TFS, no project metadata could be collected.");
			return null;
		}
		
		FieldDefinitionCollection collection = workItemClient
				.getFieldDefinitions();

		Collections.addAll(priorities, collection.get("Priority")
				.getAllowedValues().getValues());
		
		workItemClient.close();
		log.info("End Collecting project metadata " + priorities);

		return new ProjectMetadata(emptyList, emptyList, emptyList, statuses,
				priorities);
	}

	@Override
	public String getTrackerError() {
		log.info("Returning the error from the tracker.");
		return "The tracker failed to export a defect.";
	}

	@Override
	public boolean hasValidCredentials() {
		WorkItemClient workItemClient = getClient();
		
		if (workItemClient == null) {
			return false;
		}

		try {
			workItemClient.getProjects();
			return true;
		} catch (UnauthorizedException e) {
			return false;
		} finally {
            workItemClient.close();
		}
	}

	@Override
	public boolean hasValidProjectName() {
		
		if (getProjectName() == null) {
			return false;
		}
		
		WorkItemClient workItemClient = getClient();
		
		if (workItemClient == null) {
			log.warn("Unable to connect to TFS, unable to determine whether the project name was valid.");
			return false;
		}
		
		Project project = null;

		try {
			project = workItemClient.getProjects().get(getProjectName());
		} catch (UnauthorizedException | TFSUnauthorizedException e) {
			log.warn("Ran into TFSUnauthorizedException while trying to retrieve products.");
			return false;
		} finally {
			workItemClient.close();
		}
		
		log.info("Checking Project Name.");
		return project != null;
	}

	@Override
	public boolean hasValidUrl() {
		Credentials credentials = new UsernamePasswordCredentials("", "");

		URI uri;
		try {
			uri = new URI(getUrl());
		} catch (URISyntaxException e) {
			log.warn("Invalid syntax for the URL.",e);
			return false;
		}
		
		TFSTeamProjectCollection projects = new TFSTeamProjectCollection(uri,
				credentials);
		
		try {
			projects.getWorkItemClient().getProjects();
			log.info("No UnauthorizedException was thrown when attempting to connect with blank credentials.");
			return true;
		} catch (UnauthorizedException | TFSUnauthorizedException e) {
			log.info("Got an UnauthorizedException, which means that the TFS url was good.");
			return true;
		} catch (TECoreException e) {
			if (e.getMessage().contains("unable to find valid certification path to requested target")) {
				setLastError(AbstractDefectTracker.INVALID_CERTIFICATE);
				log.warn("An invalid or self-signed certificate was found.");
			}
			return false;
		}
	}
	
	@Override
	public List<Defect> getDefectList() {
		
		List<Defect> defects = new ArrayList<>();

		WorkItemClient workItemClient = getClient();
		
		if (workItemClient == null) {
			log.warn("Getting defect list failed.");
			return defects;
		}

		String wiqlQuery = "Select [System.Id] from WorkItems Where [System.TeamProject] = '" + projectName + "'";

		// Run the query and get the results.
		WorkItemCollection workItems = workItemClient.query(wiqlQuery);

		for (int i = 0; i < workItems.size(); i++) {
			WorkItem workItem = workItems.getWorkItem(i);

			Defect def = new Defect();
			def.setNativeId(String.valueOf(workItem.getID()));
			defects.add(def);
		}
		
		workItemClient.close();

		

		return defects;
	}
}
