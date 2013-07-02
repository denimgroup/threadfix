package com.denimgroup.threadfix.data.dao;

import java.util.List;

import com.denimgroup.threadfix.data.entities.ScanQueueTask;

public interface ScanQueueTaskDao {
	void saveOrUpdate(ScanQueueTask scanQueueTask);
	
	List<ScanQueueTask> retrieveAll();
	
	ScanQueueTask retrieveById(int scanQueueTaskId);
}
