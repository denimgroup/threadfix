////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.queue;

import java.util.Date;
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
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.VulnerabilityService;

/**
 * @author bbeverly
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
	@Override
	@Transactional
	public void onMessage(Message message) {
		if (message instanceof TextMessage) {
			TextMessage textMessage = (TextMessage) message;
			try {
				String text = textMessage.getText();
				
				log.info("Processing text message: " + text);
				
				if (text.equals(QueueConstants.IMPORT_SCANS_REQUEST)) {
					importScans();
				} else if (text.equals(QueueConstants.DEFECT_TRACKER_VULN_UPDATE_TYPE)) {
					syncTrackers();
				}
				
			} catch (JMSException je) {
				log.warn("The JMS message threw an error.");
				je.printStackTrace();
			}
		}

		Thread.currentThread();
		try {
			Thread.sleep(200);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		if (message instanceof MapMessage) {
			MapMessage map = (MapMessage) message;
			try {
				if (map.getString("type").equals(QueueConstants.NORMAL_SCAN_TYPE)) {
					processScanRequest(map.getInt("channelId"), map.getString("fileName"),
							map.getInt("jobStatusId"), map.getString("userName"));
				} else if (map.getString("type").equals(
						QueueConstants.DEFECT_TRACKER_VULN_UPDATE_TYPE)) {
					processDefectTrackerUpdateRequest(map.getInt("appId"),
							map.getInt("jobStatusId"));
				} else if (map.getString("type").equals(QueueConstants.SUBMIT_DEFECT_TYPE)) {
					processSubmitDefect(map.getObject("vulnerabilityIds"),
							map.getString("summary"), map.getString("preamble"),
							map.getString("component"), map.getString("version"),
							map.getString("severity"), map.getString("priority"),
							map.getString("status"), map.getInt("jobStatusId"));
				}
			} catch (JMSException e) {
				log.warn("The JMS message threw an error.");
				e.printStackTrace();
			}
		}
	}

	private void syncTrackers() {
		log.info("Syncing status with all Defect Trackers.");
		
		List<Application> apps = applicationService.loadAllActive();
		if (apps == null) {
			log.info("No applications found. Exiting.");
			return;
		}
		
		for (Application application : apps) {
			if (application != null &&
					application.getDefectTracker() != null) {
				defectService.updateVulnsFromDefectTracker(application);
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
			remoteProviderApplicationService.importScansForApplication(remoteProviderApplication);
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

		updateJobStatus(jobStatusId, "Submitting defect.");
		
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
		
		updateJobStatus(jobStatusId, "Job recieved");
		
		ApplicationChannel appChannel = applicationChannelService.loadApplicationChannel(channelId);
		
		boolean fullLog = (userName != null && appChannel != null && appChannel.getApplication() != null
				&& appChannel.getApplication().getName() != null && appChannel.getChannelType() != null
				&& appChannel.getChannelType().getName() != null);
			
		if (fullLog) {
			log.info("User " + userName + " added a " + appChannel.getChannelType().getName() + 
					" scan to the Application " + appChannel.getApplication().getName() +
					" (filename " + fileName + ").");
		}
			
		
		updateJobStatus(jobStatusId, "Processing Scan from file.");
		
		boolean finished = false, closed = false;
		
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
			} else if (!closed) {
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
	private void processDefectTrackerUpdateRequest(Integer appId, Integer jobStatusId) {
		if (appId == null) {
			closeJobStatus(jobStatusId, "Defect Tracker update failed.");
			return;
		}

		Application app = applicationService.loadApplication(appId);
		if (app == null) {
			closeJobStatus(jobStatusId, "No application found, request failed.");
			return;
		}

		updateJobStatus(jobStatusId, "Processing Defect Tracker Vulnerability update request.");
		defectService.updateVulnsFromDefectTracker(app);
		closeJobStatus(jobStatusId, "Vulnerabilities successfully updated.");
	}

	/**
	 * @param status
	 */
	@Transactional
	private void updateJobStatus(Integer id, String status) {
		
		JobStatus jobStatus = jobStatusService.loadJobStatus(id);
		
		if (jobStatus == null) {
			return;
		}
		
		if (!jobStatus.getHasStartedProcessing()) {
			jobStatus.setHasStartedProcessing(true);
		}

		jobStatus.setStatus(status);
		jobStatus.setModifiedDate(new Date());

		jobStatusService.storeJobStatus(jobStatus);
	}

	/**
	 * @param status
	 */
	@Transactional
	private void closeJobStatus(Integer id, String status) {
		JobStatus jobStatus = jobStatusService.loadJobStatus(id);
		
		
		if (jobStatus != null) {
			jobStatusService.closeJobStatus(jobStatus, status);
			jobStatus = null;
		}
	}
}
