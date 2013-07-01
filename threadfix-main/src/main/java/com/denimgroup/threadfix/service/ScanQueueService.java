package com.denimgroup.threadfix.service;

import java.util.List;

import com.denimgroup.threadfix.data.entities.ScanQueueTask;

public interface ScanQueueService {

	int queueScan(int applicationId, String scannerType);
	
	List<ScanQueueTask> loadAll();
}
