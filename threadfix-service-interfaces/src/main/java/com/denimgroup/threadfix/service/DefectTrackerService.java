////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.data.interfaces.ProjectMetadataSource;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;
import org.springframework.validation.BindingResult;

import java.util.List;

/**
 * @author bbeverly
 * 
 */
public interface DefectTrackerService {
	
	/**
	 *
	 * @param defectTracker
	 * @return
	 */
	boolean checkUrl(DefectTracker defectTracker, BindingResult result);

	/**
	 * @return
	 */
	List<DefectTracker> loadAllDefectTrackers();

	/**
	 * @param defectTrackerId
	 * @return
	 */
	DefectTracker loadDefectTracker(int defectTrackerId);

	/**
	 * @param name
	 * @return
	 */
	DefectTracker loadDefectTracker(String name);

	/**
	 * @param defectTracker
	 */
	void storeDefectTracker(DefectTracker defectTracker);

	/**
	 * @param defectTrackerId
	 */
	void deleteById(int defectTrackerId);

	/**
	 * @return
	 */
	List<DefectTrackerType> loadAllDefectTrackerTypes();

	/**
	 * @param defectTrackerTypeId
	 * @return
	 */
	DefectTrackerType loadDefectTrackerType(int defectTrackerTypeId);

    /**
     * This method only exists so that we can use AOP to intercept it
     * @param tracker the defect tracker
     * @return project metadata or null if tracker is null
     */
    ProjectMetadata getProjectMetadata(ProjectMetadataSource tracker);

	/**
	 * @param name
	 * @return
	 */
	DefectTrackerType loadDefectTrackerType(String name);

	/**
	 * @param defectTrackerType
	 */
	void storeDefectTrackerType(DefectTrackerType defectTrackerType);
}
