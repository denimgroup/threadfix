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
package com.denimgroup.threadfix.service.queue;

import java.util.List;

import javax.jms.JMSException;
import javax.jms.MapMessage;
import javax.jms.Message;
import javax.jms.MessageListener;
import javax.jms.TextMessage;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.JobStatus;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectService;
import com.denimgroup.threadfix.service.JobStatusService;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.VulnerabilityService;

/**
 * @author bbeverly
 * 
 */
@Component
@Transactional
public class QueueListener implements MessageListener {
	// TODO fix the logging to update the DB when progress is made.
	// TODO Maybe handle file scans and sentinel differently. Sentinel takes
	// way longer than normal files.
	private final Log log = LogFactory.getLog(QueueListener.class);

	private ScanMergeService scanMergeService;
	private DefectService defectService;
	private ApplicationService applicationService;
	private JobStatusService jobStatusService;
	private VulnerabilityService vulnerabilityService;
	private ApplicationChannelService applicationChannelService = null;

	private JobStatus currentJobStatus;

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
			VulnerabilityService vulnerabilityService, ApplicationChannelService applicationChannelService) {
		this.scanMergeService = scanMergeService;
		this.jobStatusService = jobStatusService;
		this.applicationService = applicationService;
		this.defectService = defectService;
		this.vulnerabilityService = vulnerabilityService;
		this.applicationChannelService = applicationChannelService;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.jms.MessageListener#onMessage(javax.jms.Message)
	 */
	@Override
	public void onMessage(Message message) {
		if (message instanceof TextMessage) {
			TextMessage textMessage = (TextMessage) message;
			try {
				log.info(textMessage.getText());
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
							map.getString("severity"), map.getInt("jobStatusId"));
				}
			} catch (JMSException e) {
				log.warn("The JMS message threw an error.");
				e.printStackTrace();
			}
		}
	}

	/**
	 * @param vulnerabilities
	 * @param summary
	 * @param preamble
	 * @param jobStatusId
	 */
	private void processSubmitDefect(Object vulnerabilityIds, String summary, String preamble,
			String component, String version, String severity, Integer jobStatusId) {

		getJobStatus(jobStatusId);

		@SuppressWarnings("unchecked")
		List<Vulnerability> vulnerabilities = vulnerabilityService
				.loadVulnerabilityList((List<Integer>) vulnerabilityIds);
		if (vulnerabilities == null) {
			closeJobStatus("No vulnerabilities could be found");
			return;
		}

		Vulnerability vuln = vulnerabilities.get(0);
		Defect defect = defectService.createDefect(vulnerabilities, summary, preamble, component,
				version, severity);

		if (defect == null) {
			if (vuln.getApplication() == null) {
				closeJobStatus("The defect could not be created.");
				return;
			} else {
				closeJobStatus(defectService.getErrorMessage(vulnerabilities));
				return;
			}
		}

		closeJobStatus("Defect was created successfully.");
	}

	/**
	 * @param channelId
	 * @param fileName
	 * @param jobStatusId
	 */
	private void processScanRequest(Integer channelId, String fileName, Integer jobStatusId, String userName) {
		// TODO Move the jobStatus updating to the importer to improve messages
		// once the messages persist
		
		ApplicationChannel appChannel = applicationChannelService.loadApplicationChannel(channelId);
		
		boolean fullLog = (userName != null && appChannel != null && appChannel.getApplication() != null
				&& appChannel.getApplication().getName() != null && appChannel.getChannelType() != null
				&& appChannel.getChannelType().getName() != null);
			
		if (fullLog) {
			log.info("User " + userName + " added a " + appChannel.getChannelType().getName() + 
					" scan to the Application " + appChannel.getApplication().getName() +
					" (filename " + fileName + ").");
		}
			
		getJobStatus(jobStatusId);
		updateJobStatus("Processing Scan from file.");
		boolean finished = scanMergeService.processScan(channelId, fileName);

		if (finished) {
			closeJobStatus("Scan completed.");
			if (fullLog) {
				log.info("The " + appChannel.getChannelType().getName() + " scan from User " + userName + " on Application " + appChannel.getApplication().getName()
					+ " (filename " + fileName + ") completed successfully.");
			}
		} else {
			closeJobStatus("Scan encountered an error.");
			if (fullLog) {
				log.info("The " + appChannel.getChannelType().getName() + " scan from User " + userName + " on Application " + appChannel.getApplication().getName()
					+ " (filename " + fileName + ") did not complete successfully.");
			}
		}
	}

	/**
	 * @param appId
	 * @param jobStatusId
	 */
	private void processDefectTrackerUpdateRequest(Integer appId, Integer jobStatusId) {
		getJobStatus(jobStatusId);
		if (appId == null) {
			closeJobStatus("Defect Tracker update failed.");
			return;
		}

		Application app = applicationService.loadApplication(appId);
		if (app == null) {
			closeJobStatus("No application found, request failed.");
			return;
		}

		updateJobStatus("Processing Defect Tracker Vulnerability update request.");
		defectService.updateVulnsFromDefectTracker(app);
		closeJobStatus("Vulnerabilities successfully updated.");
	}

	/**
	 * @param jobStatusId
	 */
	private void getJobStatus(Integer jobStatusId) {
		currentJobStatus = jobStatusService.loadJobStatus(jobStatusId);
	}

	/**
	 * @param status
	 */
	private void updateJobStatus(String status) {
		if (currentJobStatus != null) {
			jobStatusService.updateJobStatus(currentJobStatus, status);
		}
	}

	/**
	 * @param status
	 */
	private void closeJobStatus(String status) {
		if (currentJobStatus != null) {
			jobStatusService.closeJobStatus(currentJobStatus, status);
			currentJobStatus = null;
		}
	}
}
