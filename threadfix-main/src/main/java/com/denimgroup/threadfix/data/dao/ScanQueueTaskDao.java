package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.ScanQueueTask;

public interface ScanQueueTaskDao {
	void saveOrUpdate(ScanQueueTask scanQueueTask);
}
