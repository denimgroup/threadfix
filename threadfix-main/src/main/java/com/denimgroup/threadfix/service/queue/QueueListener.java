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
package com.denimgroup.threadfix.service.queue;

import java.util.List;

import javax.jms.JMSException;
import javax.jms.MapMessage;
import javax.jms.Message;
import javax.jms.MessageListener;
import javax.jms.TextMessage;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.JobStatus;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectService;
import com.denimgroup.threadfix.service.JobStatusService;
import com.denimgroup.threadfix.service.RemoteProviderApplicationService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService.ResponseCode;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.VulnerabilityService;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Component
public class QueueListener implements MessageListener {

	protected final SanitizedLogger log = new SanitizedLogger(QueueListener.class);

	private ScanMergeService scanMergeService;
	private DefectService defectService;
	private ApplicationService applicationService;
	private JobStatusService jobStatusService;
	private VulnerabilityService vulnerabilityService;
	private ApplicationChannelService applicationChannelService = null;
	private RemoteProviderApplicationService remoteProviderApplicationService = null;
	private RemoteProviderTypeService remoteProviderTypeService = null;

	/**
	 * @param scanMergeService
	 * @param jobStatusService
	 * @param applicationService
	 * @param defectService
	 * @param vulnerabilityService
	 */
	@Autowired
	public QueueListener(ScanMergeService scanMergeService, JobStatusService jobStatusService,
			ApplicationService applicationService, DefectService defectService,
			VulnerabilityService vulnerabilityService,
			ApplicationChannelService applicationChannelService,
			RemoteProviderApplicationService remoteProviderApplicationService,
			RemoteProviderTypeService remoteProviderTypeService) {
		this.scanMergeService = scanMergeService;
		this.jobStatusService = jobStatusService;
		this.applicationService = applicationService;
		this.defectService = defectService;
		this.vulnerabilityService = vulnerabilityService;
		this.applicationChannelService = applicationChannelService;
		this.remoteProviderApplicationService = remoteProviderApplicationService;
		this.remoteProviderTypeService = remoteProviderTypeService;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.jms.MessageListener#onMessage(javax.jms.Message)
	 */
	@Transactional(readOnly=false)
	@Override
	public void onMessage(Message message) {
		try {
			
			if (message instanceof TextMessage) {
				TextMessage textMessage = (TextMessage) message;
				String text = textMessage.getText();
				
				log.info("Processing text message: " + text);
				
				switch(text) {
					case QueueConstants.IMPORT_SCANS_REQUEST            : importScans();  break;
					case QueueConstants.DEFECT_TRACKER_VULN_UPDATE_TYPE : syncTrackers(); break;
				}
			}

			if (message instanceof MapMessage) {
				MapMessage map = (MapMessage) message;
			
				String type = map.getString("type");
				
				switch (type) {
					case QueueConstants.NORMAL_SCAN_TYPE :
						processScanRequest(map.getInt("channelId"), map.getString("fileName"),
								map.getInt("jobStatusId"), map.getString("userName"));
						break;
						
					case QueueConstants.DEFECT_TRACKER_VULN_UPDATE_TYPE:
						processDefectTrackerUpdateRequest(map.getInt("appId"),
								map.getInt("jobStatusId"));
						break;
						
					case QueueConstants.SUBMIT_DEFECT_TYPE:
						processSubmitDefect(map.getObject("vulnerabilityIds"),
								map.getString("summary"), map.getString("preamble"),
								map.getString("component"), map.getString("version"),
								map.getString("severity"), map.getString("priority"),
								map.getString("status"), map.getInt("jobStatusId"));
						break;
						
					case QueueConstants.IMPORT_REMOTE_PROVIDER_SCANS_REQUEST:
						processRemoteProviderBulkImport(map.getInt("remoteProviderTypeId"),
								map.getInt("jobStatusId"));
						break;
				}
			}
			
		} catch (JMSException e) {
			log.warn("The JMS message threw an error.");
			e.printStackTrace();
		}
	}

	private void processRemoteProviderBulkImport(Integer remoteProviderTypeId, Integer jobStatusId) {
		log.info("Remote Provider Bulk Import job received");
		jobStatusService.updateJobStatus(jobStatusId, "Remote Provider Bulk Import job received");
		
		ResponseCode response = remoteProviderTypeService.importScansForApplications(remoteProviderTypeId);
		
		String message;
		
		switch (response) {
			case BAD_ID:   message = "Remote Provider Bulk Import job failed because no remote provider type was found."; break;
			case NO_APPS:  message = "Remote Provider Bulk Import job failed because no apps were found";                 break;
			case SUCCESS:  message = "Remote Provider Bulk Import job completed.";                                        break;
			default:       message = "Remote Provider Bulk Import encountered an unknown error";
		}
		
		log.info(message);
		
		jobStatusService.updateJobStatus(jobStatusId, message);
	}

	private void syncTrackers() {
		log.info("Syncing status with all Defect Trackers.");
		
		List<Application> apps = applicationService.loadAllActive();
		if (apps == null) {
			log.info("No applications found. Exiting.");
			return;
		}
		
		for (Application application : apps) {
			if (application != null && application.getDefectTracker() != null) {
				defectService.updateVulnsFromDefectTracker(application.getId());
			}
		}
		
		log.info("Finished updating Defect status for all Applications.");
	}

	private void importScans() {
		log.info("Importing scans for all Remote Provider Applications.");
		List<RemoteProviderApplication> apps = remoteProviderApplicationService.loadAllWithMappings();
		
		if (apps == null || apps.size() == 0) {
			log.info("No apps with mappings found. Exiting.");
			return;
		}
		
		for (RemoteProviderApplication remoteProviderApplication : apps) {
			if (remoteProviderApplication == null || remoteProviderApplication.getRemoteProviderType() == null) {
				continue;
			}
			remoteProviderTypeService.decryptCredentials(remoteProviderApplication.getRemoteProviderType());
			remoteProviderTypeService.importScansForApplications(remoteProviderApplication.getId());
		}
		
		log.info("Completed requests for scan imports.");
	}

	/**
	 * @param vulnerabilities
	 * @param summary
	 * @param preamble
	 * @param jobStatusId
	 */
	private void processSubmitDefect(Object vulnerabilityIds, String summary, String preamble,
			String component, String version, String severity, String priority,
			String status, Integer jobStatusId) {

		jobStatusService.updateJobStatus(jobStatusId, "Submitting defect.");
		
		@SuppressWarnings("unchecked")
		List<Vulnerability> vulnerabilities = vulnerabilityService
				.loadVulnerabilityList((List<Integer>) vulnerabilityIds);
		
		if (vulnerabilities == null) {
			closeJobStatus(jobStatusId, "No vulnerabilities could be found");
			return;
		}

		Vulnerability vuln = vulnerabilities.get(0);
		Defect defect = defectService.createDefect(vulnerabilities, summary,
				preamble, component, version, severity, priority, status);

		if (defect == null) {
			if (vuln == null || vuln.getApplication() == null) {
				closeJobStatus(jobStatusId, "The defect could not be created.");
				return;
			} else {
				closeJobStatus(jobStatusId, defectService.getErrorMessage(vulnerabilities));
				return;
			}
		}

		closeJobStatus(jobStatusId, "Defect was created successfully.");
	}

	/**
	 * @param channelId
	 * @param fileName
	 * @param jobStatusId
	 */
	private void processScanRequest(Integer channelId, String fileName, Integer jobStatusId, String userName) {
		// TODO Move the jobStatus updating to the importer to improve messages
		// once the messages persist
		
		jobStatusService.updateJobStatus(jobStatusId, "Job received");
		
		ApplicationChannel appChannel = applicationChannelService.loadApplicationChannel(channelId);
		
		boolean fullLog = userName != null && appChannel != null && appChannel.getApplication() != null
				&& appChannel.getApplication().getName() != null && appChannel.getChannelType() != null
				&& appChannel.getChannelType().getName() != null;
			
		if (fullLog) {
			log.info("User " + userName + " added a " + appChannel.getChannelType().getName() +
					" scan to the Application " + appChannel.getApplication().getName() +
					" (filename " + fileName + ").");
		}
		
		jobStatusService.updateJobStatus(jobStatusId, "Processing Scan from file.");
		
		boolean finished = false;
		
		try {
			finished = scanMergeService.processScan(channelId, fileName, jobStatusId, userName);
		} catch (OutOfMemoryError e) {
			closeJobStatus(jobStatusId, "Scan encountered an out of memory error and did not complete correctly.");
			log.warn("Encountered out of memory error. Closing job status and rethrowing exception.",e);
			throw e;
		} finally {
			if (finished) {
				closeJobStatus(jobStatusId, "Scan completed.");
				if (fullLog) {
					log.info("The " + appChannel.getChannelType().getName() + " scan from User "
						+ userName + " on Application " + appChannel.getApplication().getName()
						+ " (filename " + fileName + ") completed successfully.");
				}
			} else {
				closeJobStatus(jobStatusId, "Scan encountered an error.");
				if (fullLog) {
					log.info("The " + appChannel.getChannelType().getName() + " scan from User "
						+ userName + " on Application " + appChannel.getApplication().getName()
						+ " (filename " + fileName + ") did not complete successfully.");
				}
			}
		}
	}

	/**
	 * @param appId
	 * @param jobStatusId
	 */
	@Transactional(readOnly=false)
	private void processDefectTrackerUpdateRequest(Integer appId, Integer jobStatusId) {
		if (appId == null) {
			closeJobStatus(jobStatusId, "Defect Tracker update failed because it received a null application ID");
			return;
		}

		jobStatusService.updateJobStatus(jobStatusId, "Processing Defect Tracker Vulnerability update request.");
		boolean result = defectService.updateVulnsFromDefectTracker(appId);
		
		if (result) {
			closeJobStatus(jobStatusId, "Vulnerabilities successfully updated.");
		} else {
			closeJobStatus(jobStatusId, "Vulnerability update failed.");
		}
	}

	/**
	 * @param status
	 */
	private void closeJobStatus(Integer id, String status) {
		JobStatus jobStatus = jobStatusService.loadJobStatus(id);
		
		if (jobStatus != null) {
			jobStatusService.closeJobStatus(jobStatus, status);
			jobStatus = null;
		}
	}
}
