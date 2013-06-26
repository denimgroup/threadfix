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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

import org.hibernate.annotations.Type;

@Entity
@Table(name="ScanQueueItem")
public class ScanQueueItem extends AuditableEntity {

	private static final long serialVersionUID = 886166865576713403L;
	
	private int taskId;
	private int applicationId;
	
	//	TODO - Determine if this is a String or a string/enumeration
	private String scanner;
	//	TODO - Determine if we need to treat this different
	private String version;
	
	private long startTime;
	private long endTime;
	private long timeoutTime;
	//	TODO - Make an enumeration for the various status options
	private int status;
	private String scanAgentInfo;

	@Column(nullable=false)
	public int getTaskId() {
		return(this.taskId);
	}
	
	public void setTaskId(int taskId) {
		this.taskId = taskId;
	}
	
	@Column(nullable=false)
	public int getApplicationId() {
		return(this.applicationId);
	}
	
	public void setApplicationId(int applicationId) {
		this.applicationId = applicationId;
	}
	
	@Column(nullable=false)
	public String getScanner() {
		return(this.scanner);
	}
	
	public void setScanner(String scanner) {
		this.scanner = scanner;
	}
	
	@Column
	public String getVersion() {
		return(this.version);
	}
	
	public void setVersion(String version) {
		this.version = version;
	}
	
	@Column (nullable=false)
	public long getStartTime() {
		return(this.startTime);
	}
	
	public void setStartTime(long startTime) {
		this.startTime = startTime;
	}
	
	@Column
	public long getEndTime() {
		return(this.endTime);
	}
	
	public void setEndTime(long endTime) {
		this.endTime = endTime;
	}
	
	@Column(nullable=false)
	public long getTimeoutTime() {
		return(this.timeoutTime);
	}
	
	public void setTimeoutTime(long timeoutTime) {
		this.timeoutTime = timeoutTime;
	}
	
	@Column(nullable=false)
	public int getStatus() {
		return(this.status);
	}
	
	public void setStatus(int status) {
		this.status = status;
	}
	
	@Column(nullable=false)
	@Type(type="text")
	public String getScanAgentInfo() {
		return(this.scanAgentInfo);
	}
	
	public void setScanAgentInfo(String scanAgentInfo) {
		this.scanAgentInfo = scanAgentInfo;
	}
}
