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
package com.denimgroup.threadfix.service.queue;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.RemoteProviderTypeService.ResponseCode;
import javax.annotation.Nullable;

import com.denimgroup.threadfix.service.GRCToolService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.jms.*;
import java.util.List;
import java.util.Map;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Component
public class QueueListener implements MessageListener {

	protected final SanitizedLogger log = new SanitizedLogger(QueueListener.class);

    @Autowired
	private ScanMergeService scanMergeService;
    @Autowired
	private DefectService defectService;
    @Autowired(required=false)
	private GRCToolService grcToolService;
    @Autowired
	private ApplicationService applicationService;
    @Autowired
	private JobStatusService jobStatusService;
    @Autowired
	private VulnerabilityService vulnerabilityService;
    @Autowired
	private ApplicationChannelService applicationChannelService = null;
    @Autowired
	private RemoteProviderApplicationService remoteProviderApplicationService = null;
    @Autowired
    private OrganizationService organizationService;
    @Autowired
	private RemoteProviderTypeService remoteProviderTypeService = null;
    @Autowired
    private QueueSender queueSender;
    @Autowired(required=false)
    @Nullable
    private ScanQueueService scanQueueService = null;
    @Autowired
    private VulnerabilityFilterService vulnerabilityFilterService;
    @Autowired
    private EmailReportService emailReportService;
    @Autowired
    private ScheduledEmailReportService scheduledEmailReportService;

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
					case QueueConstants.IMPORT_SCANS_REQUEST            : importScans();     break;
					case QueueConstants.DEFECT_TRACKER_VULN_UPDATE_TYPE : syncTrackers();    break;
					case QueueConstants.GRC_CONTROLS_UPDATE_TYPE        : syncGrcControls(); break;
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

					case QueueConstants.GRC_CONTROLS_UPDATE_TYPE:
						processGrcControlsUpdateRequest(map.getInt("appId"),
								map.getInt("jobStatusId"));
						break;
						
					case QueueConstants.SUBMIT_DEFECT_TYPE:
						processSubmitDefect(map.getObject("vulnerabilityIds"),
								map.getString("summary"), map.getString("preamble"),
								map.getString("component"), map.getString("version"),
								map.getString("severity"), map.getString("priority"),
								map.getString("status"), map.getInt("jobStatusId"),
                                map.getBoolean("additionalScannerInfo"));
						break;
						
					case QueueConstants.IMPORT_REMOTE_PROVIDER_SCANS_REQUEST:
						processRemoteProviderBulkImport(map.getInt("remoteProviderTypeId"),
								map.getInt("jobStatusId"));
						break;
                    case QueueConstants.SCHEDULED_SCAN_TYPE:
                        processScheduledScan(map.getInt("appId"),
                                map.getString("scanner"));
                        break;
                    case QueueConstants.STATISTICS_UPDATE:
                        processStatisticsUpdate(map.getInt("appId"));
                        break;
                    case QueueConstants.VULNS_FILTER:
                        updateVulnsFilter();
                        break;
                    case QueueConstants.SEND_EMAIL_REPORT:
                        processSendEmailReport(map.getInt("scheduledEmailReportId"));
				}
			}
			
		} catch (JMSException e) {
			log.warn("The JMS message threw an error.");
			e.printStackTrace();
		}
	}

    private void processSendEmailReport(int scheduledEmailReportId) {
        log.info("Schedule Email Report was called! With scheduledEmailReportId=" + scheduledEmailReportId);
        ScheduledEmailReport scheduledEmailReport = scheduledEmailReportService.loadById(scheduledEmailReportId);
        emailReportService.sendEmailReport(scheduledEmailReport);
    }

    private void updateVulnsFilter() {
        log.info("Starting updating all filter vulnerabilities");
        vulnerabilityFilterService.updateAllVulnerabilities();
        log.info("Updating all filter vulnerabilities finished.");
    }

    private void processStatisticsUpdate(int appId) {
        if (appId == -1) {
            log.info("Processing statistics update for all apps.");

            for (Organization organization : organizationService.loadAllActive()) {
                for (Application app : organization.getActiveApplications()) {
                    vulnerabilityService.updateVulnerabilityReport(app);
                }
            }
        } else {
            log.info("Processing statistics update for application with ID " + appId);
            vulnerabilityService.updateVulnerabilityReport(
                    applicationService.loadApplication(appId)
            );
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

        queueSender.updateAllCachedStatistics();
		
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

    private void syncGrcControls() {
        if (grcToolService == null) {
            return;
        }

		log.info("Syncing status with all GRC Controls.");

		List<Application> apps = applicationService.loadAllActive();
		if (apps == null) {
			log.info("No applications found. Exiting.");
			return;
		}

		for (Application application : apps) {
			if (application != null && application.getGrcTool() != null) {
				grcToolService.updateControlsFromGrcTool(application.getId());
			}
		}

		log.info("Finished updating Control status for all Applications.");
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

        queueSender.updateAllCachedStatistics();

		log.info("Completed requests for scan imports.");
	}

	/**
	 */
	private void processSubmitDefect(Object vulnerabilityIds, String summary, String preamble,
			String component, String version, String severity, String priority,
			String status, Integer jobStatusId, Boolean additionalScannerInfo) {

		jobStatusService.updateJobStatus(jobStatusId, "Submitting defect.");
		
		@SuppressWarnings("unchecked")
		List<Vulnerability> vulnerabilities = vulnerabilityService
				.loadVulnerabilityList((List<Integer>) vulnerabilityIds);
		
		if (vulnerabilities == null) {
			closeJobStatus(jobStatusId, "No vulnerabilities could be found");
			return;
		}

		Vulnerability vuln = vulnerabilities.get(0);
		Map<String, Object> map = defectService.createDefect(vulnerabilities, summary,
				preamble, component, version, severity, priority, status, null, additionalScannerInfo);

        Defect defect = null;
        if (map.get(DefectService.DEFECT) instanceof Defect)
            defect = (Defect) map.get(DefectService.DEFECT);
		if (defect == null) {
			if (vuln == null || vuln.getApplication() == null) {
				closeJobStatus(jobStatusId, map.get(DefectService.ERROR) == null ?
                        "The defect could not be created." : map.get(DefectService.ERROR).toString());
				return;
			} else {
				closeJobStatus(jobStatusId, defectService.getErrorMessage(vulnerabilities));
				return;
			}
		}

		closeJobStatus(jobStatusId, "Defect was created successfully.");
	}

	/**
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

                if (appChannel != null && appChannel.getApplication() != null) {
                    queueSender.updateCachedStatistics(appChannel.getApplication().getId());
                }

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
	 * @param appId
	 * @param jobStatusId
	 */
	@Transactional(readOnly=false)
	private void processGrcControlsUpdateRequest(Integer appId, Integer jobStatusId) {
		if (appId == null) {
			closeJobStatus(jobStatusId, "GRC Controls update failed because it received a null application ID");
			return;
		}

		jobStatusService.updateJobStatus(jobStatusId, "Processing GRC Controls update request.");
		boolean result = grcToolService.updateControlsFromGrcTool(appId);

		if (result) {
			closeJobStatus(jobStatusId, "GRC Controls successfully updated.");
		} else {
			closeJobStatus(jobStatusId, "GRC Control update failed.");
		}
	}

    /**
     * @param appId
     * @param scanner
     */
    @Transactional(readOnly=false)
    private void processScheduledScan(int appId, String scanner) {
        if (scanQueueService == null) {
            return;
        }

        Application application = applicationService.loadApplication(appId);
        if (application == null)
            return;

        ScanQueueTask scanTask = scanQueueService.queueScan(appId, scanner);
        if (scanTask == null || scanTask.getId() < 0) {
            log.warn("Adding scan queue task " + scanner +" for application with Id " + appId + " was failed.");
        } else {
            log.info("Scan Queue Task ID " + scanTask.getId() + " was successfully added to the application with ID " + appId);
        }
    }

	/**
	 * @param status
	 */
	private void closeJobStatus(Integer id, String status) {
		JobStatus jobStatus = jobStatusService.loadJobStatus(id);
		
		if (jobStatus != null) {
			jobStatusService.closeJobStatus(jobStatus, status);
		}
	}
}
