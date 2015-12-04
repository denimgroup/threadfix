////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/**
 * @author bbeverly
 * 
 */
public final class DefectTrackerFactory {

	protected static final SanitizedLogger STATIC_LOG = new SanitizedLogger(DefectTrackerFactory.class);
	
	private DefectTrackerFactory(){}
	
	/**
	 * Returns an AbstractDefectTracker implementation based on the
	 * DefectTrackerType name.
	 * 
	 * Be sure to decrypt the application credentials if you want this to work.
	 * 
	 * @param application
	 * @return
	 */
	public static AbstractDefectTracker getTracker(Application application) {
		if (application == null || application.getDefectTracker() == null
				|| application.getDefectTracker().getDefectTrackerType() == null
				|| application.getDefectTracker().getDefectTrackerType().getName() == null) {
			STATIC_LOG.warn("Application was not configured with a Defect Tracker correctly.");
			return null;
		}
			
		AbstractDefectTracker tracker = getTracker(application.getDefectTracker()
															  .getDefectTrackerType());
		
		if (tracker == null) {
			return null;
		}
		
		return configureTracker(tracker, application);
	}

	public static AbstractDefectTracker getTracker(DefectTracker defectTracker) {
		if (defectTracker == null
				|| defectTracker.getDefectTrackerType() == null
				|| defectTracker.getDefectTrackerType().getName() == null) {
			STATIC_LOG.warn("Defect Tracker was not configured correctly.");
			return null;
		}

		AbstractDefectTracker tracker = getTracker(defectTracker.getDefectTrackerType());

		if (tracker == null) {
			return null;
		}

		return configureTracker(tracker, defectTracker);
	}

	public static AbstractDefectTracker getTrackerByType(DefectTracker defectTracker, String userName,
			String password) {
		if (defectTracker == null) {
			STATIC_LOG.warn("getDefectTrackerByType was given an incorrect type.");
			return null;
		}
		
		AbstractDefectTracker tracker = getTracker(defectTracker.getDefectTrackerType());
		
		if (tracker == null) {
			return null;
		}
		
		return configureTracker(tracker, defectTracker.getUrl(), userName, password);
	}
	
	public static AbstractDefectTracker getTracker(DefectTrackerType type) {
		if (type == null || type.getName() == null ) {
			return null;
		}
		
		if (type.getName().equals(DefectTrackerType.BUGZILLA)) {
			return new BugzillaDefectTracker();
		} else if (type.getName().equals(DefectTrackerType.JIRA)) {
			return new JiraDefectTracker();
		} else if (type.getName().equals(DefectTrackerType.MICROSOFT_TFS)) {
			return new TFSDefectTracker();
        } else if (type.getName().equals(DefectTrackerType.HP_QUALITYCENTER)) {
            return new HPQualityCenterDefectTracker();
        } else if (type.getName().equals(DefectTrackerType.VERSION_ONE)) {
            return new VersionOneDefectTracker();
        } else {
			
			// Must be a legitimate Java identifier
			if (type.getFullClassName() != null) {
				Exception exception = null;
	
				STATIC_LOG.info("A non-standard Defect Tracker type was requested. Attempting to load using Class.forName()");
				
				try {
					Class<?> customTrackerClass = Class.forName(type.getFullClassName());
	
					Constructor<?>[] constructors = customTrackerClass.getConstructors();
					for (Constructor<?> constructor : constructors) {
						if (constructor.getParameterAnnotations() != null && constructor.getParameterAnnotations().length == 0) {
							return (AbstractDefectTracker) constructor.newInstance();
						}
					}
	
				} catch (ClassNotFoundException e) {
					exception = e;
				} catch (IllegalArgumentException e) {
					exception = e;
				} catch (InstantiationException e) {
					exception = e;
				} catch (IllegalAccessException e) {
					exception = e;
				} catch (InvocationTargetException e) {
					exception = e;
				}
	
				if (exception != null) {
					STATIC_LOG.error("The custom importer has not been correctly added. " +
							"Put the JAR in the lib directory of threadfix under the webapps folder in tomcat.", exception);
				}
			}
				
			STATIC_LOG.warn("Failed to load a Defect Tracker implementation.");
			return null;
		}
	}

	private static AbstractDefectTracker configureTracker(AbstractDefectTracker tracker, String url, 
			String username, String password) {
		
		tracker.setUrl(url);
		tracker.setUsername(username);
		tracker.setPassword(password);

		return tracker;
	}
	
	private static AbstractDefectTracker configureTracker(
			AbstractDefectTracker tracker, Application application) {

		tracker.setProjectName(application.getProjectName());
		tracker.setProjectId(application.getProjectId());

		boolean appIsSetToUseDefaults =
				application.isUseDefaultCredentials() != null && application.isUseDefaultCredentials();
		boolean defectTrackerHasDefaults =
				application.getDefectTracker().getDefaultUsername() != null &&
				application.getDefectTracker().getDefaultPassword() != null;

        if (appIsSetToUseDefaults && defectTrackerHasDefaults) {
            tracker.setUsername(application.getDefectTracker().getDefaultUsername());
            tracker.setPassword(application.getDefectTracker().getDefaultPassword());
        } else {
            tracker.setUsername(application.getUserName());
            tracker.setPassword(application.getPassword());
        }
        tracker.setUrl(application.getDefectTracker().getUrl());

		return tracker;
	}

	private static AbstractDefectTracker configureTracker(
			AbstractDefectTracker tracker, DefectTracker defectTracker) {

		tracker.setProjectName(defectTracker.getDefaultProductName());

		tracker.setUsername(defectTracker.getDefaultUsername());
		tracker.setPassword(defectTracker.getDefaultPassword());
		tracker.setUrl(defectTracker.getUrl());

		return tracker;
	}
}
