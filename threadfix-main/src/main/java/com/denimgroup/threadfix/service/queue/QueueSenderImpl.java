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

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ExceptionLog;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ChannelSeverityService;
import com.denimgroup.threadfix.service.ExceptionLogService;
import com.denimgroup.threadfix.service.JobStatusService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService;
import com.denimgroup.threadfix.service.UserService;
import org.apache.activemq.command.ActiveMQMapMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.jms.JMSException;
import javax.jms.MapMessage;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;

/**
 * @author bbeverly
 * 
 */
@Service
@Transactional
public class QueueSenderImpl implements QueueSender {
	protected final SanitizedLogger log = new SanitizedLogger(QueueSenderImpl.class);

    @Autowired
    private ExceptionLogService exceptionLogService;
	@Autowired
	private JmsTemplate jmsTemplate = null;
	@Autowired
	private JobStatusService jobStatusService = null;
    @Autowired
    private RemoteProviderTypeService remoteProviderTypeService;
	@Autowired
	private UserService userService;
	@Autowired
	private ChannelSeverityService channelSeverityService;

    private static final SimpleDateFormat format = new SimpleDateFormat("MMM d, y h:mm:ss a");

	String jmsErrorString = "The JMS system encountered an error that prevented the message from being correctly created.";

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.queue.QueueSender#startDefectTrackerSync
	 * ()
	 */
	@Override
	public void startDefectTrackerSync() {
		send(QueueConstants.DEFECT_TRACKER_VULN_UPDATE_TYPE);
	}

    /*
	 * (non-Javadoc)
	 *
	 * @see
	 * com.denimgroup.threadfix.service.queue.QueueSender#startDefectTrackerSync
	 * ()
	 */
	@Override
	public void startGrcToolSync() {
		send(QueueConstants.GRC_CONTROLS_UPDATE_TYPE);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * com.denimgroup.threadfix.service.queue.QueueSender#startImportScans()
	 */
	@Override
	public void startImportScans() {
		send(QueueConstants.IMPORT_SCANS_REQUEST);
	}

	@Override
	public void startEmailReport(Integer scheduledEmailReportId){
		MapMessage emailReportMap = new ActiveMQMapMessage();
		try {
			emailReportMap.setInt("scheduledEmailReportId", scheduledEmailReportId);
			emailReportMap.setString("type", QueueConstants.SEND_EMAIL_REPORT);
		} catch (JMSException e) {
			log.error(jmsErrorString);
			addExceptionLog(e);
		}
		sendMap(emailReportMap);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.queue.QueueSender#addScanToQueue(java
	 * .lang.String, java.lang.Integer)
	 */
	@Override
	public void addScanToQueue(String fileName, Integer channelId, Integer orgId, Integer appId,
			Calendar calendar, ApplicationChannel applicationChannel) {

		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		
		log.info("User " + userName + " is adding a scan to the queue with the file name " + fileName + ".");
		
		MapMessage scanMap = new ActiveMQMapMessage();
		try {
			scanMap.setString("userName", userName);
			scanMap.setInt("channelId", channelId);
			scanMap.setString("fileName", fileName);
			scanMap.setString("type", QueueConstants.NORMAL_SCAN_TYPE);
			scanMap.setString("urlPath", "/organizations/" + orgId
					+ "/applications/" + appId);
			scanMap.setString("urlText", "Go to Application");
		} catch (JMSException e) {
			log.error(jmsErrorString);
            addExceptionLog(e);
		}

		sendMap(scanMap, calendar, applicationChannel);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.queue.QueueSender#addDefectTrackerVulnUpdate
	 * (java.lang.Integer )
	 */
	@Override
	public void addDefectTrackerVulnUpdate(Integer orgId, Integer appId) {
		
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		
		log.info("User " + userName + " is adding a defect tracker update for application with ID " + appId + ".");

		if (appId == null)
			return;

		MapMessage defectTrackerVulnMap = new ActiveMQMapMessage();

		Integer userId = null;
		User user = userService.getCurrentUser();
		if (user != null) {
			userId = user.getId();
		}

		try {
			defectTrackerVulnMap.setInt("appId", appId);
			defectTrackerVulnMap.setObject("userId", userId);
			defectTrackerVulnMap.setString("type", QueueConstants.DEFECT_TRACKER_VULN_UPDATE_TYPE);
			defectTrackerVulnMap.setString("urlPath",
					"/organizations/" + orgId + "/applications/" + appId);
			defectTrackerVulnMap.setString("urlText", "Go to Application");
		} catch (JMSException e) {
			log.error(jmsErrorString);
            addExceptionLog(e);
		}

		sendMap(defectTrackerVulnMap);
	}

	@Override
	public void addGrcToolVulnUpdate(Integer orgId, Integer appId) {

		String userName = SecurityContextHolder.getContext().getAuthentication().getName();

		log.info("User " + userName + " is adding a GRC Controls update for application with ID " + appId + ".");

		if (appId == null)
			return;

		MapMessage grcToolVulnMap = new ActiveMQMapMessage();

		try {
			grcToolVulnMap.setInt("appId", appId);
			grcToolVulnMap.setString("type", QueueConstants.GRC_CONTROLS_UPDATE_TYPE);
			grcToolVulnMap.setString("urlPath",
					"/organizations/" + orgId + "/applications/" + appId);
			grcToolVulnMap.setString("urlText", "Go to Application");
		} catch (JMSException e) {
			log.error(jmsErrorString);
            addExceptionLog(e);
		}

		sendMap(grcToolVulnMap);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.queue.QueueSender#addSubmitDefect(java
	 * .lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public void addSubmitDefect(List<Integer> vulnerabilityIds, String summary, 
			String preamble, String component, String version, String severity, 
			String priority, String status, Integer orgId, Integer applicationId) {
		
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		
		log.info("User " + userName + " is adding a defect submission to the queue for " + vulnerabilityIds.size() + " vulnerabilities from Application with ID " + applicationId + ".");
		
		MapMessage submitDefectMap = new ActiveMQMapMessage();

		try {
			submitDefectMap.setObject("vulnerabilityIds", vulnerabilityIds);
			submitDefectMap.setString("summary", summary);
			submitDefectMap.setString("preamble", preamble);
			submitDefectMap.setString("component", component);
			submitDefectMap.setString("version", version);
			submitDefectMap.setString("severity", severity);
			submitDefectMap.setString("priority", priority);
			submitDefectMap.setString("status", status);
			submitDefectMap.setString("type", QueueConstants.SUBMIT_DEFECT_TYPE);
			submitDefectMap.setString("urlPath", "/organizations/"
					+ orgId + "/applications/" + applicationId + "/defects");
			submitDefectMap.setString("urlText", "Submit more defects");
		} catch (JMSException e) {
			log.error(jmsErrorString);
            addExceptionLog(e);
		}

		sendMap(submitDefectMap);
	}


	@Override
    public void addRemoteProviderImport(int remoteProviderTypeId) {
		addRemoteProviderImport(remoteProviderTypeService.load(remoteProviderTypeId));
	}

    @Override
	public void addRemoteProviderImport(RemoteProviderType remoteProviderType) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            String userName = authentication.getName();
            log.info("User " + userName + " is adding a remote provider import to the queue for " +
                    remoteProviderType.getName() + ".");
        } else {
            log.info("Scheduled Job is adding a remote provider import to the queue for " +
                    remoteProviderType.getName() + ".");
        }

		MapMessage remoteProviderImportMap = new ActiveMQMapMessage();

		try {
			remoteProviderImportMap.setObject("remoteProviderTypeId", remoteProviderType.getId());
			remoteProviderImportMap.setString("type", QueueConstants.IMPORT_REMOTE_PROVIDER_SCANS_REQUEST);
		} catch (JMSException e) {
			log.error(jmsErrorString);
            addExceptionLog(e);
		}

		sendMap(remoteProviderImportMap);
	}

	@Override
	public void addScheduledScanById(int scheduledScanId) {
		if (scheduledScanId < 0)
			return;

		MapMessage scheduledScanMap = new ActiveMQMapMessage();

		try {
			scheduledScanMap.setInt("scheduledScanId", scheduledScanId);
			scheduledScanMap.setString("type", QueueConstants.SCHEDULED_SCAN_TYPE);
		} catch (JMSException e) {
			log.error(jmsErrorString);
			addExceptionLog(e);
		}

		sendMap(scheduledScanMap);
	}

	@Override
    public void updateCachedStatistics(int appId) {
        MapMessage scheduledScanMap = new ActiveMQMapMessage();

        try {
            scheduledScanMap.setInt("appId", appId);
            scheduledScanMap.setString("type", QueueConstants.STATISTICS_UPDATE);
        } catch (JMSException e) {
            log.error(jmsErrorString);
            addExceptionLog(e);
        }

        sendMap(scheduledScanMap);
    }

    @Override
    public void updateAllCachedStatistics() {
        MapMessage scheduledScanMap = new ActiveMQMapMessage();

        try {
            scheduledScanMap.setInt("appId", -1);
            scheduledScanMap.setString("type", QueueConstants.STATISTICS_UPDATE);
        } catch (JMSException e) {
            log.error(jmsErrorString);
            addExceptionLog(e);
        }

        sendMap(scheduledScanMap);
    }

    @Override
    public void updateVulnFilter() {

        MapMessage scheduledScanMap = new ActiveMQMapMessage();

        try {
            scheduledScanMap.setString("type", QueueConstants.VULNS_FILTER);
        } catch (JMSException e) {
            log.error(jmsErrorString);
            addExceptionLog(e);
        }

        sendMap(scheduledScanMap);
    }

	@Override
	public void updateTeamCachedStatistics(int orgId) {
		MapMessage scheduledScanMap = new ActiveMQMapMessage();

		try {
			scheduledScanMap.setInt("teamId", orgId);
			scheduledScanMap.setString("type", QueueConstants.STATISTICS_TEAM_UPDATE);
		} catch (JMSException e) {
			log.error(jmsErrorString);
			addExceptionLog(e);
		}

		sendMap(scheduledScanMap);
	}

	@Override
	public void updateChannelSeverityMappings(String channelSeverityIds) {
		MapMessage channelSeverityMappingsMap = new ActiveMQMapMessage();

		try {
			channelSeverityMappingsMap.setString("channelSeverityIds", channelSeverityIds);
			channelSeverityMappingsMap.setString("type", QueueConstants.CHANNEL_SEVERITY_MAPPINGS);
		} catch (JMSException e) {
			log.error(jmsErrorString);
			addExceptionLog(e);
		}

		sendMap(channelSeverityMappingsMap);
	}

	@Override
	public void deleteVulnFilter(int channelTypeId, String channelVulnName) {
		MapMessage channelVulnFilterMap = new ActiveMQMapMessage();

		try {
			channelVulnFilterMap.setInt("channelTypeId", channelTypeId);
			channelVulnFilterMap.setString("channelVulnName", channelVulnName);
			channelVulnFilterMap.setString("type", QueueConstants.DELETE_CHANNEL_VULN_FILTER);
		} catch (JMSException e) {
			log.error(jmsErrorString);
			addExceptionLog(e);
		}

		sendMap(channelVulnFilterMap);
	}

	private void send(String message) {
		jmsTemplate.convertAndSend("requestQueue", message);
	}

	private void sendMap(MapMessage map) {
		sendMap(map, null, null);
	}
	
	private void sendMap(MapMessage map, Calendar calendar, ApplicationChannel applicationChannel) {
		try {
			if (map.getString("type") != null) {
				Integer jobStatusId = jobStatusService.createNewJobStatus(map.getString("type"),
						"Sent to Queue", map.getString("urlPath"), map.getString("urlText"), 
						calendar, applicationChannel);
				map.setInt("jobStatusId", jobStatusId);
				jmsTemplate.convertAndSend("requestQueue", map);
			}
		} catch (JMSException e) {
			log.error(jmsErrorString);
            addExceptionLog(e);
		}
	}

    private void addExceptionLog(Exception e) {
        ExceptionLog exceptionLog = new ExceptionLog(e);
        exceptionLogService.storeExceptionLog(exceptionLog);
        log.error("Uncaught exception - logging at " + format.format(exceptionLog.getTime().getTime()) + ".");
    }
}
