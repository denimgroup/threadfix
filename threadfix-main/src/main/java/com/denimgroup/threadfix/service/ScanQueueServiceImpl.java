package com.denimgroup.threadfix.service;

import java.util.Calendar;
import java.util.Date;

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

@Service
@Transactional(readOnly = false)
public class ScanQueueServiceImpl implements ScanQueueService {

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
			myTask.setCreateTime(new Date());
			Calendar myCal = Calendar.getInstance();
			//	TOFIX - Actually calculate the max finish time
			myCal.add(Calendar.HOUR, 12);
			myTask.setTimeoutTime(myCal.getTime());
			myTask.setScanner(scannerType);
			//	TOFIX - Actually make statuses
			myTask.setStatus(1);
			myTask.setScanAgentInfo("Junk Scan Agent Info");
			
			scanQueueTaskDao.saveOrUpdate(myTask);
		} else {
			//	TOFIX - Log this errors
		}
		
		return(retVal);
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
