////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//     All rights reserved worldwide.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.ScanQueueTask;

import java.util.List;

public interface ScanQueueTaskDao extends GenericObjectDao<ScanQueueTask> {
	
	List<ScanQueueTask> retrieveAvailable();

	void delete(ScanQueueTask task);
}
