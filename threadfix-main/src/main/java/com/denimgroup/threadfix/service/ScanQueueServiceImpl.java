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
