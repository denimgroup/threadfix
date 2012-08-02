////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.defects;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;

/**
 * @author bbeverly
 * 
 */
public class DefectTrackerFactory {

	private final Log log = LogFactory.getLog(this.getClass());
	private static final Log STATIC_LOG = LogFactory.getLog("DefectTrackerFactory");
	
	public static boolean checkTrackerUrl(String url, DefectTrackerType type) {
		STATIC_LOG.info("Checking Defect Tracker URL.");
		
		if (type != null && type.getName() != null && url != null) {
			
			String name = type.getName();
			
			AbstractDefectTracker tracker = null;
			
			DefectTracker emptyTracker = new DefectTracker();
			emptyTracker.setUrl(url);
			
			if (name.equals(DefectTrackerType.JIRA)) {
				tracker = getJiraDefectTracker(emptyTracker,null,null);
			} else if (name.equals(DefectTrackerType.BUGZILLA)) {
				tracker = getBugzillaDefectTracker(emptyTracker,null,null);
			} else {
				STATIC_LOG.warn("Defect Tracker type was not found.");
				return false;
			}
			
			if (tracker != null) {
				STATIC_LOG.info("Passing check to Defect Tracker.");
				return tracker.hasValidUrl();
			}
		}
		
		STATIC_LOG.warn("Incorrectly configured Defect Tracker in checkTrackerURL. Returning false.");
		return false;
	}
	
	/**
	 * Returns an AbstractDefectTracker implementation based on the
	 * defecttrackertype name.
	 * 
	 * @param application
	 * @return
	 */
	public AbstractDefectTracker getTracker(Application application) {
		if (application == null || application.getDefectTracker() == null
				|| application.getDefectTracker().getDefectTrackerType() == null
				|| application.getDefectTracker().getDefectTrackerType().getName() == null) {
			log.warn("Application was not configured with a Defect Tracker correctly.");
			return null;
		}

		if (application.getDefectTracker().getDefectTrackerType().getName()
				.equals(DefectTrackerType.JIRA)) {
			return getJiraDefectTracker(application);
		} else if (application.getDefectTracker().getDefectTrackerType().getName()
				.equals(DefectTrackerType.BUGZILLA)) {
			return getBugzillaDefectTracker(application);
		} else {
			log.warn("An unsupported Defect Tracker type was requested.");
			return null;
		}
	}

	public AbstractDefectTracker getTrackerByType(DefectTracker defectTracker, String userName,
			String password) {
		if (defectTracker == null) {
			log.warn("getDefectTrackerByType was given an incorrect type.");
			return null;
		}
		if (defectTracker.getDefectTrackerType().getName().equals(DefectTrackerType.BUGZILLA)) {
			return getBugzillaDefectTracker(defectTracker, userName, password);
		} else if (defectTracker.getDefectTrackerType().getName().equals(DefectTrackerType.JIRA)) {
			return getJiraDefectTracker(defectTracker, userName, password);
		} else {
			log.warn("An unsupported Defect Tracker type was requested.");
			return null;
		}
	}

	/**
	 * Gets a Bugzilla defect tracker using credentials from an
	 * applicationdefecttracker.
	 * 
	 * @param application
	 * @return
	 */
	public BugzillaDefectTracker getBugzillaDefectTracker(Application application) {
		if (application == null || application.getDefectTracker() == null) {
			return null;
		}

		BugzillaDefectTracker bugzilla = new BugzillaDefectTracker();
		bugzilla.setServerPassword(application.getPassword());
		bugzilla.setServerURL(application.getDefectTracker().getUrl());
		bugzilla.setServerUsername(application.getUserName());
		bugzilla.setServerProject(application.getProjectName());
		bugzilla.setServerProjectId(application.getProjectId());

		return bugzilla;
	}

	/**
	 * Gets a Bugzilla defect tracker using user name, password, and project
	 * name
	 * 
	 * @param userName
	 * @param password
	 * @param projectName
	 * @return
	 */
	public static BugzillaDefectTracker getBugzillaDefectTracker(DefectTracker defectTracker,
			String userName, String password) {
		BugzillaDefectTracker bugzilla = new BugzillaDefectTracker();
		bugzilla.setServerURL(defectTracker.getUrl());
		bugzilla.setServerUsername(userName);
		bugzilla.setServerPassword(password);
		// bugzilla.setServerProject(projectName);

		return bugzilla;
	}

	/**
	 * Gets a Jira defect tracker using credentials from an
	 * applicationdefecttracker.
	 * 
	 * @param application
	 * @return
	 */
	public JiraDefectTracker getJiraDefectTracker(Application application) {
		if (application == null || application.getDefectTracker() == null) {
			return null;
		}

		JiraDefectTracker jira = new JiraDefectTracker();
		jira.setProjectName(application.getProjectName());
		jira.setProjectId(application.getProjectId());
		jira.setPassword(application.getPassword());
		jira.setUrl(application.getDefectTracker().getUrl());
		jira.setUsername(application.getUserName());

		return jira;
	}

	/**
	 * Gets a Jira defect tracker using user name, password, and project name
	 * 
	 * @param userName
	 * @param password
	 * @param projectName
	 * @return
	 */
	public static JiraDefectTracker getJiraDefectTracker(DefectTracker defectTracker, String userName,
			String password) {
		JiraDefectTracker jira = new JiraDefectTracker();
		jira.setUrl(defectTracker.getUrl());
		jira.setUsername(userName);
		jira.setPassword(password);
		// jira.setPassword(projectName);

		return jira;
	}
}
