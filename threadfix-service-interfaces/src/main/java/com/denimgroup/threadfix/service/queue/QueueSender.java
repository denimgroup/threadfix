////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.queue;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;

import java.util.Calendar;
import java.util.List;

/**
 * @author bbeverly
 * 
 */
public interface QueueSender {

	/**
	 * 
	 */
	 void startGrcToolSync();

	/**
	 *
	 */
	void startDefectTrackerSync();

	/**
	 * 
	 */
	void startImportScans();

    /**
     * @param emailReportJobId
     */
	void startEmailReport(Integer emailReportJobId);

	/**
	 * @param fileName
	 * @param channelId
	 */
	void addScanToQueue(String fileName, Integer channelId, Integer orgId, Integer appId,
						Calendar calendar, ApplicationChannel applicationChannel);

	/**
	 * @param orgId
	 * @param appId
	 */
	void addDefectTrackerVulnUpdate(Integer orgId, Integer appId);

	/**
	 * @param orgId
	 * @param appId
	 */
	void addGrcToolVulnUpdate(Integer orgId, Integer appId);

	/**
	 * @param vulns
	 * @param summary
	 * @param preamble
	 * @param component
	 * @param version
	 * @param severity
	 */
	void addSubmitDefect(List<Integer> vulns, String summary, String preamble,
						 String component, String version, String severity, String priority,
						 String status, Integer orgId, Integer applicationId);

	/**
	 * @param remoteProviderType
	 */
	void addRemoteProviderImport(RemoteProviderType remoteProviderType);

    /**
     * @param remoteProviderTypeId
     */
    void addRemoteProviderImport(int remoteProviderTypeId);

	void addScheduledScanById(int scheduledScanId);

    void updateCachedStatistics(int appId);

    void updateAllCachedStatistics();

    void updateVulnFilter();

	void updateVulnFilterWithOldGenericVulnId(int oldGenericVulnId);

	void updateTeamCachedStatistics(int orgId);

	void updateChannelSeverityMappings(String channelSeverityIds);

	void deleteVulnFilter(int channelFilterId);

	void findSharedVulns();
}
