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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.AcceptanceCriteria;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.BindingResult;

import java.util.List;
import java.util.Set;

/**
 * @author bbeverly
 * 
 */
public interface ApplicationService {

	/**
	 * @return
	 */
	List<Application> loadAllActive();
	
	/**
	 * 
	 * @return
	 */
	List<Application> loadAllActiveFilter(Set<Integer> authenticatedTeamIds);

	/**
	 * @param applicationId
	 * @return
	 */
	Application loadApplication(int applicationId);

	/**
	 * @param applicationName
	 * @return
	 */
	Application loadApplication(String applicationName, int teamId);

	/**
     * @param applicationUniqueId
     * @return
     */
    Application loadApplicationByUniqueId(String applicationUniqueId, int teamId);

    /**
	 * @param application
	 */
	void storeApplication(Application application, EventAction eventAction);

	/**
	 * Prepare the application for deletion.
	 * 
	 * @param application
	 */
	void deactivateApplication(Application application);

	/**
	 * 
	 * @param application
	 * @param result
	 * @return true if the defect tracker has changed, false otherwise
	 */
	boolean validateApplicationDefectTracker(Application application,
			BindingResult result);

	/**
	 * This method is used to validate incoming REST application parameters.
	 * @param application
	 * @return
	 */
	boolean checkApplication(Application application);
	
	/**
	 * Removes WAF rules from an Application if the WAF has changed or been removed.
	 * Don't save the Application after using this method as it does not handle removing
	 * WAF rules from the application because the application may be out of session,
	 * causing it to throw an error when you try to access the WAF rules at all.
	 * @param application
	 */
	void updateWafRules(Application application, Integer dbApplicationWafId);
	
	/**
	 * Performs necessary checks and keeps the controller layer clean.
	 * @param application
	 * @param result
	 */
	void validateAfterEdit(Application application, BindingResult result);
	
	/**
	 * Performs necessary checks and keeps the controller layer clean.
	 * @param application
	 * @param result
	 */
	void validateAfterCreate(Application application, BindingResult result);
	
	/**
	 * If the project root has been updated, this method updates the associated vulns.
	 * @param application
	 */
	void updateProjectRoot(Application application);

	/**
	 * 
	 * @param appId
	 * @return
	 */
	List<Vulnerability> getVulnTable(int appId, TableSortBean bean);

	/**
	 * 
	 * @param appId
	 * @param bean
	 * @return
	 */
	long getCount(Integer appId, TableSortBean bean);

	/**
	 * 
	 * @param application
	 * @return
	 */
	Application decryptCredentials(Application application);

    /**
     *
     * @param application
     * @return
     */
    Application encryptRepositoryCredentials(Application application);

    /**
     *
     * @param application
     * @return
     */
    Application decryptRepositoryCredentials(Application application);

	/**
	 * 
	 * @param organizations
	 */
	void generateVulnerabilityReports(List<Organization> organizations);

	/**
	 * 
	 * @param organization
	 */
	void generateVulnerabilityReports(Organization organization);

	/**
	 * 
	 * @param appId
	 * @param open
	 * @return
	 */
	long getVulnCount(Integer appId, boolean open);

	/**
	 * 
	 */
	void validateDefectTracker(Application application, BindingResult result);

    long getUnmappedFindingCount(Integer appId);

	long getApplicationCount();

    Object updateApplicationFromREST(Integer applicationId, MultiValueMap<String, String> params, BindingResult result);

    List<AcceptanceCriteria> loadUnassociatedAcceptanceCriteria(Application application);

}
