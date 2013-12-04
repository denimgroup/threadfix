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

package com.denimgroup.threadfix.data.entities;

import com.denimgroup.threadfix.data.entities.TaskConfig;
import org.jetbrains.annotations.NotNull;

public class Task {

    @NotNull
	private String taskType;
	private TaskConfig taskConfig;
    private int taskId;
	private String secureTaskKey;
	
	public Task() {
		
	}
	
	public Task(int taskId, @NotNull String taskType, TaskConfig taskConfig) {
		this.taskId = taskId;
		this.taskType = taskType;
		this.taskConfig = taskConfig;
	}

	public int getTaskId() {
		return taskId;
	}

	public void setTaskId(int taskId) {
		this.taskId = taskId;
	}

	public String getTaskType() {
		return(this.taskType);
	}
	
	public void setTaskType(@NotNull String taskType) {
		this.taskType = taskType;
	}
	
	public TaskConfig getTaskConfig() {
		return(this.taskConfig);
	}
	
	public void setTaskConfig(TaskConfig taskConfig) {
		this.taskConfig = taskConfig;
	}
	
	public String getSecureTaskKey() {
		return secureTaskKey;
	}

	public void setSecureTaskKey(String secureTaskKey) {
		this.secureTaskKey = secureTaskKey;
	}

	public String toString() {
		String retVal = "Task { taskType=" + this.taskType + ", taskConfig=" + taskConfig + "}";
		return(retVal);
	}
}
