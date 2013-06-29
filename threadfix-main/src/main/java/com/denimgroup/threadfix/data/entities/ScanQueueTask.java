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

import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.annotations.Type;

@Entity
@Table(name="ScanQueueTask")
public class ScanQueueTask extends AuditableEntity {

	private static final long serialVersionUID = 886166865576713403L;
	
	private int taskId;
	private Application application;
	private List<ScanStatus> scanStatuses;
	
	//	TODO - Determine if this is a String or a string/enumeration
	private String scanner;
	//	TODO - Determine if we need to treat this different
	private String version;
	
	private Date createTime;
	private Date startTime;
	private Date endTime;
	private Date timeoutTime;
	//	TODO - Make an enumeration for the various status options
	private int status;
	private String scanAgentInfo;

	@Column
	public int taskId() {
		return(this.taskId);
	}
	
	public void taskId(int taskId) {
		this.taskId = taskId;
	}
	
	@OneToMany(mappedBy = "scanQueueTask", cascade = CascadeType.ALL)
	public List<ScanStatus> getScanStatuses() {
		return(this.scanStatuses);
	}
	
	public void setScanStatuses(List<ScanStatus> scanStatuses) {
		this.scanStatuses = scanStatuses;
	}

	@ManyToOne
	@JoinColumn(name = "applicationId")
	@JsonIgnore
	public Application getApplication() {
		return(this.application);
	}
	
	public void setApplication(Application application) {
		this.application = application;
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
	
	
	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable=false)
	public Date getCreateTime() {
		return createTime;
	}

	public void setCreateTime(Date createTime) {
		this.createTime = createTime;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column
	public Date getStartTime() {
		return startTime;
	}

	public void setStartTime(Date startTime) {
		this.startTime = startTime;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column
	public Date getEndTime() {
		return endTime;
	}

	public void setEndTime(Date endTime) {
		this.endTime = endTime;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column
	public Date getTimeoutTime() {
		return timeoutTime;
	}

	public void setTimeoutTime(Date timeoutTime) {
		this.timeoutTime = timeoutTime;
	}

	@Column(nullable=false)
	public int getStatus() {
		return(this.status);
	}
	
	public void setStatus(int status) {
		this.status = status;
	}
	
	@Column
	@Type(type="text")
	public String getScanAgentInfo() {
		return(this.scanAgentInfo);
	}
	
	public void setScanAgentInfo(String scanAgentInfo) {
		this.scanAgentInfo = scanAgentInfo;
	}
}
