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

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ScanQueueTaskDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ScanQueueTask;
import com.denimgroup.threadfix.data.entities.ScanStatus;
import com.denimgroup.threadfix.data.entities.TaskConfig;

@Service
@Transactional(readOnly = false)
public class ScanQueueServiceImpl implements ScanQueueService {
	
	protected final SanitizedLogger log = new SanitizedLogger(ScanQueueServiceImpl.class);

	private ApplicationDao applicationDao;
	private ChannelTypeDao channelTypeDao;
	private ApplicationChannelDao applicationChannelDao;
	private ScanQueueTaskDao scanQueueTaskDao;
	
	@Autowired
	public ScanQueueServiceImpl(ApplicationDao applicationDao,
								ChannelTypeDao channelTypeDao,
								ApplicationChannelDao applicationChannelDao,
								ScanQueueTaskDao scanQueueTaskDao) {
		this.applicationDao = applicationDao;
		this.channelTypeDao = channelTypeDao;
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
			//	TOFIX - Actually calculate the max finish time
			myCal.add(Calendar.HOUR, 12);
			myTask.setTimeoutTime(myCal.getTime());
			myTask.setScanner(scannerType);
			myTask.setStatus(ScanQueueTask.STATUS_QUEUED);
			myTask.setScanAgentInfo("Junk Scan Agent Info");
			
			ScanStatus scanStatus = new ScanStatus();
			scanStatus.setTimestamp(now);
			scanStatus.setMessage("Scan queued at");
			
			scanStatus.setScanQueueTask(myTask);
			
			myTask.addScanStatus(scanStatus);
			
			
			scanQueueTaskDao.saveOrUpdate(myTask);
			retVal = myTask.getId();
			log.info("Created ScanQueueTask with id: " + retVal);
		} else {
			log.warn("Invalid applicationId of " + applicationId + " provided. No scan queued");
		}
		
		return(retVal);
	}
	
	public boolean taskStatusUpdate(int taskId, String message) {
		boolean retVal = false;
		
		ScanQueueTask task = this.scanQueueTaskDao.retrieveById(taskId);
		if(task != null) {
			ScanStatus status = new ScanStatus();
			status.setTimestamp(new Date());
			status.setMessage(message);
			task.addScanStatus(status);
			this.scanQueueTaskDao.saveOrUpdate(task);
			retVal = true;
		}
		
		return(retVal);
	}
	
	@Override
	public List<ScanQueueTask> loadAll() {
		List<ScanQueueTask> retVal;
		
		retVal = scanQueueTaskDao.retrieveAll();
		
		return(retVal);
	}
	
	@Override
	public ScanQueueTask retrieveById(int scanQueueTaskId) {
		ScanQueueTask retVal = scanQueueTaskDao.retrieveById(scanQueueTaskId);
		return(retVal);
	}
	
	@Override
	public Object requestTask(String scanners, String agentConfig) {
		TaskConfig retVal = null;
		
		if(scanners == null) {
			log.warn("Attempting to request a task with a null list of scanners. Aborting.");
			return(null);
		} else if(scanners.length() == 0) {
			log.warn("Attempting to request a task with an empty list of scanners. Aborting.");
			return(null);
		} else {
			log.debug("Requesting a task for one of these scanners: " + scanners);
		}
		
		String[] scannerArray = scanners.split(",");
		
		List<ScanQueueTask> availableTasks = this.scanQueueTaskDao.retrieveAvailable();
		
		for(ScanQueueTask task : availableTasks) {
			log.debug("Examining task: " + task + " to see if we can run it");
			for(String scanner : scannerArray) {
				if(scanner.equals(task.getScanner())) {
					log.info("Found a task for available scanner: " + scanner + ": " + task);
					//	TOFIX - Look up the TaskConfig for this particular task instead of lazily
					//	returning a hacked together version
					retVal = new TaskConfig();
					retVal.setTargetUrlString("http://localhost:8080/bodgeit/");
					retVal.setConfigParam("exampleParam1", "exampleValue1");
					retVal.setConfigParam("exampleParam2", "example Value 2 With Spaces");
					retVal.setDataBlob("dataBlob1", new byte[] { 0x00, 0x01, 0x02, 0x03 } );
					retVal.setDataBlob("dataBlob2", new byte[] { -127, -126, -125, -124 } );
					
					//	Mark the task as having been assigned
					//	TODO - Make sure we're doing everything we need here to set this up to run (end time?)
					task.setStartTime(new Date());
					task.setStatus(ScanQueueTask.STATUS_ASSIGNED);
					
					ScanStatus status = new ScanStatus();
					status.setScanQueueTask(task);
					status.setTimestamp(new Date());
					status.setMessage("Assigning task to an agent with agentConfig: " + agentConfig);
					
					task.addScanStatus(status);
					
					this.scanQueueTaskDao.saveOrUpdate(task);
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
		
		log.info("Found a suitable task for the agent: " + retVal);
		
		return(retVal);
	}
	
	/**
	 * Run through all items in the scan queue and clear out any scans
	 * that have timed out.
	 * 
	 * TOFIX - Implement me!
	 */
	private void cleanScanQueue() {
		//	TOFIX - Implement me!
	}
	
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
	
	private ApplicationChannel retrieveAppropriateApplicationChannel() {
		//	TOFIX - Implement me!
		
		/*
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
		*/
		return(null);
	}

}
