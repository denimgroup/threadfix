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

package com.denimgroup.threadfix.service;

import java.sql.Blob;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.DocumentDao;
import com.denimgroup.threadfix.data.dao.ScanQueueTaskDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Document;
import com.denimgroup.threadfix.data.entities.ScanQueueTask;
import com.denimgroup.threadfix.data.entities.ScanQueueTask.ScanQueueTaskStatus;
import com.denimgroup.threadfix.data.entities.ScanStatus;
import com.denimgroup.threadfix.data.entities.Task;
import com.denimgroup.threadfix.data.entities.TaskConfig;

@Service
@Transactional(readOnly = false)
public class ScanQueueServiceImpl implements ScanQueueService {
	
	protected final SanitizedLogger log = new SanitizedLogger(ScanQueueServiceImpl.class);

	private ApplicationDao applicationDao;
	private DocumentDao documentDao;
	private ApplicationChannelDao applicationChannelDao;
	private ScanQueueTaskDao scanQueueTaskDao;
	
	@Autowired
	public ScanQueueServiceImpl(ApplicationDao applicationDao,
								DocumentDao documentDao,
								ApplicationChannelDao applicationChannelDao,
								ScanQueueTaskDao scanQueueTaskDao) {
		this.applicationDao = applicationDao;
		this.documentDao = documentDao;
		this.applicationChannelDao = applicationChannelDao;
		this.scanQueueTaskDao = scanQueueTaskDao;
	}
	
	@Override
	public int queueScan(int applicationId, String scannerType) {
		int retVal = -2;
		
		Application application = applicationDao.retrieveById(applicationId);
		if(application != null) {
			ScanQueueTask myTask = new ScanQueueTask();
			myTask.setApplication(application);
			Date now = new Date();
			myTask.setCreateTime(now);
			Calendar myCal = Calendar.getInstance();
			//	TODO - Actually calculate the max finish time
			myCal.add(Calendar.HOUR, 12);
			myTask.setTimeoutTime(myCal.getTime());
			myTask.setScanner(scannerType);
			myTask.setStatus(ScanQueueTaskStatus.STATUS_QUEUED.getValue());
			//	TODO - See if we really need ScanAgentInfo here because that really only
			//	matters once an agent "claims" the task to execute.
			myTask.setScanAgentInfo("<Junk Scan Agent Info>");
			
			ScanStatus scanStatus = new ScanStatus();
			scanStatus.setTimestamp(now);
			SimpleDateFormat format = new SimpleDateFormat("dd-MM-yy:HH:mm:SS Z");
			scanStatus.setMessage("Scan queued at: " + format.format(now));
			
			scanStatus.setScanQueueTask(myTask);
			
			myTask.addScanStatus(scanStatus);
			
			
			scanQueueTaskDao.saveOrUpdate(myTask);
			retVal = myTask.getId();
			log.info("Created ScanQueueTask with id: " + retVal);
		} else {
			log.warn("Invalid applicationId of " + applicationId + " provided. No scan queued");
		}
		
		return retVal;
	}
	
	@Override
	public boolean taskStatusUpdate(int taskId, String message) {
		boolean retVal = false;
		
		ScanQueueTask task = this.scanQueueTaskDao.retrieveById(taskId);
		if(task != null) {
			ScanStatus status = new ScanStatus();
			status.setScanQueueTask(task);
			status.setTimestamp(new Date());
			status.setMessage(message);
			task.addScanStatus(status);
			this.scanQueueTaskDao.saveOrUpdate(task);
			retVal = true;
		}
		
		return retVal;
	}
	
	@Override
	public List<ScanQueueTask> loadAll() {
		List<ScanQueueTask> retVal;
		
		retVal = scanQueueTaskDao.retrieveAll();
		
		return retVal;
	}
	
	@Override
	public ScanQueueTask retrieveById(int scanQueueTaskId) {
		return scanQueueTaskDao.retrieveById(scanQueueTaskId);
	}
	
	@Override
	public Object requestTask(String scanners, String agentConfig, String secureTaskKey) {
		Task retVal = null;
		
		if(scanners == null) {
			log.warn("Attempting to request a task with a null list of scanners. Aborting.");
			return null;
		} else if(scanners.length() == 0) {
			log.warn("Attempting to request a task with an empty list of scanners. Aborting.");
			return null;
		} else {
			log.info("Requesting a task for one of these scanners: " + scanners);
		}
		
		String[] scannerArray = scanners.split(",");
		
		List<ScanQueueTask> availableTasks = this.scanQueueTaskDao.retrieveAvailable();
		
		if(availableTasks == null) {
			log.warn("List of available tasks was null.");
		} else if (availableTasks.size() == 0) {
			log.info("Length of list of available tasks was 0. No tasks in queue.");
		} else {
			log.info("Looking through " + availableTasks.size() + " possible tasks to find a match.");

            for(ScanQueueTask task : availableTasks) {
                log.info("Examining task: " + task + " to see if we can run it");
                for(String scanner : scannerArray) {
                    if(scanner.equals(task.getScanner())) {
                        log.info("Found a task for available scanner: " + scanner + ": " + task);

                        retVal = new Task();
                        retVal.setTaskId(task.getId());
                        retVal.setTaskType(task.getScanner());
                        TaskConfig taskConfig = new TaskConfig();

                        if (task.getApplication().getUrl() == null || task.getApplication().getUrl().isEmpty()) {
                            String msg = "URL for application " + task.getApplication().getId() + " needs to be set.";
                            log.warn(msg);
                            return msg;
                        }

                        taskConfig.setTargetUrlString(task.getApplication().getUrl());

                        //	See if there is a configuration file specified for this Application and scanner type
                        int appId = task.getApplication().getId();

                        Document configDoc = this.documentDao.retrieveByAppIdAndFilename(appId, task.getScannerShortName(), ScanQueueTask.SCANAGENT_CONFIG_FILE_EXTENSION);

                        if(configDoc != null) {
                            Blob fileData = configDoc.getFile();
                            //	Note that JDBC Blobs should start their data at index 1 not 0
                            try {
                                taskConfig.setDataBlob("configFile", fileData.getBytes(1, (int)fileData.length()));
                                log.debug("Successfully added configFile data to taskConfig");
                            } catch (SQLException e) {
                                log.warn("Unable to retrieve Blob data because of exception. "
                                            + "Will fight through, but config will not be returned with task. "
                                            + "Message was: " + e.getMessage(), e);
                            }
                        } else {
                            log.debug("No Document (configFile) data found to be associated with app: "
                                        + task.getApplication().getId() + " and scanner: " + task.getScanner());
                        }

                        retVal.setTaskConfig(taskConfig);
                        retVal.setSecureTaskKey(secureTaskKey);

                        //	Mark the task as having been assigned
                        //	TODO - Make sure we're doing everything we need here to set this up to run (end time?)
                        task.setStartTime(new Date());
                        task.setStatus(ScanQueueTaskStatus.STATUS_ASSIGNED.getValue());

                        ScanStatus status = new ScanStatus();
                        status.setScanQueueTask(task);
                        status.setTimestamp(new Date());
                        status.setMessage("Assigning task to an agent with agentConfig:\n" + agentConfig);

                        task.addScanStatus(status);
                        task.setSecureKey(secureTaskKey);

                        this.scanQueueTaskDao.saveOrUpdate(task);
                        log.info("Scanner: " + scanner + " matched the task and the task has been assigned: " + task);
                        break;
                    } else {
                        log.debug("Scanner: " + scanner + " doesn't match task: " + task);
                    }
                }

                //	If an available scanner matches this task, pick it and move on
                if(retVal != null) {
                    break;
                }
            }
        }
		
		if(retVal != null) {
			log.info("Found a suitable task for the agent: " + retVal);
		} else {
			log.info("No suitable tasks found for the agent. Returning null.");
		}
		
		return retVal;
	}
	
	@Override
	public boolean completeTask(int scanQueueTaskId) {

		Date now = new Date();
		SimpleDateFormat format = new SimpleDateFormat("dd-MM-yy:HH:mm:SS Z");
		String message = "Scan completed successfully at: " + format.format(now);

		return changeTaskStatusWithMessage(scanQueueTaskId, now, ScanQueueTaskStatus.STATUS_COMPLETE_SUCCESSFUL, message);
	}
	
	@Override
	public boolean failTask(int scanQueueTaskId, String message) {
		boolean retVal;
		
		retVal = changeTaskStatusWithMessage(scanQueueTaskId, new Date(), ScanQueueTaskStatus.STATUS_COMPLETE_FAILED, message);
		
		return retVal;
	}
	
	private boolean changeTaskStatusWithMessage(int scanQueueTaskId, Date timestamp,
                                                @NotNull ScanQueueTaskStatus newStatus, String message) {
		boolean retVal;
		
		ScanQueueTask task = this.retrieveById(scanQueueTaskId);
		
		ScanStatus status = new ScanStatus();
		status.setScanQueueTask(task);
//		SimpleDateFormat format = new SimpleDateFormat("dd-MM-yy:HH:mm:SS Z");
		status.setMessage(message);
		status.setTimestamp(timestamp);
		
		task.setEndTime(timestamp);
		task.setStatus(newStatus.getValue());
		task.addScanStatus(status);
		
		this.scanQueueTaskDao.saveOrUpdate(task);
		retVal = true;
		
		return retVal;
	}
	
	/**
	 * Run through all items in the scan queue and clear out any scans
	 * that have timed out.
	 * 
	 * private void cleanScanQueue() {
		//	TOFIX - Implement me!
	   }
	 */
	
	
	/**
	 * TODO - Refactor because this was copied from ScanServiceImpl
	 * 
	 */
	public boolean isDuplicate(ApplicationChannel applicationChannel) {
		if (applicationChannel.getApplication() == null
				|| applicationChannel.getChannelType().getId() == null) {
			return true;
		}
		
		ApplicationChannel dbAppChannel = applicationChannelDao.retrieveByAppIdAndChannelId(
				applicationChannel.getApplication().getId(), applicationChannel.getChannelType()
						.getId());
		return dbAppChannel != null && !applicationChannel.getId().equals(dbAppChannel.getId());
	}
	
	/* TODO - Implement me!
	 * private ApplicationChannel retrieveAppropriateApplicationChannel() {
		
		
		
		if (channel != null) {
			return channel.getId();
		} else {
			channel = new ApplicationChannel();
			channel.setChannelType(channelType);
			application.getChannelList().add(channel);
			channel.setApplication(application);
			channel.setScanList(new ArrayList<Scan>());
			
			channel.setApplication(application);
			if (!isDuplicate(channel)) {
				applicationChannelDao.saveOrUpdate(channel);
				return channel.getId();
			}
		}
		
		return(null);
	}
	*/

	@Override
	public ScanQueueTask loadTaskById(int taskId) {
		return scanQueueTaskDao.retrieveById(taskId);
	}

	@Override
	public String deactivateTask(ScanQueueTask task) {
		task.setActive(false);
		task.setEndTime(new Date());
		scanQueueTaskDao.saveOrUpdate(task);
		return null;
	}

	@Override
	public String deleteTask(ScanQueueTask task) {
		Application application = applicationDao.retrieveById(task.getApplication().getId());
		if (application == null) {
			return "Task couldn't be deleted. Something happened...";
		}
		
		application.getScanQueueTasks().remove(task);
		task.setApplication(null);
		scanQueueTaskDao.delete(task);
		applicationDao.saveOrUpdate(application);
		return null;
	}

}
