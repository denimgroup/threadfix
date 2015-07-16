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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.ScanQueueTask;
import com.denimgroup.threadfix.data.entities.Task;
import org.springframework.validation.BindingResult;

import java.util.List;

public interface ScanQueueService {

    ScanQueueTask queueScan(int applicationId, String scannerType);
	
	List<ScanQueueTask> loadAll();
	
	ScanQueueTask retrieveById(int scanQueueTaskId);
	
	boolean taskStatusUpdate(int taskId, String message);
	
	Task requestTask(String scanners, String agentConfig, String secureTaskKey, String scanAgentKey) throws ScanQueueTaskConfigException;
	
	void completeTask(int scanQueueTaskId);
	
	void failTask(int scanQueueTaskId, String message);

	ScanQueueTask loadTaskById(int taskId);

	void deactivateTask(ScanQueueTask task);

	void deleteTask(ScanQueueTask task);

	String validate(ScanQueueTask scanQueueTask);

	ScanQueueTask queueScanTask(int appId, ScanQueueTask scanQueueTask);

	ScanQueueTask queueScanWithConfig(int appId, String scannerType, String scanConfigId);

	ScanQueueTask queueScanWithScheduledScanId(int scheduledScanId);
}
