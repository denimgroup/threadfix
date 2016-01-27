////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.util.Calendar;
import java.util.Date;

@Entity
@Table(name = "JobStatus")
public class JobStatus extends BaseEntity {

	private static final long serialVersionUID = 8339606417348417904L;
	
	private ApplicationChannel applicationChannel;

	private String status;
	private String type;
	private String urlText;
	private String urlPath;
	private Calendar scanDate;
	private Date startDate;
	private Date endDate;
	private Date modifiedDate;
	private boolean open = true;
	private boolean startedProcessing = false;

	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable = true)
	public Calendar getScanDate() {
		return scanDate;
	}

	public void setScanDate(Calendar scanDate) {
		this.scanDate = scanDate;
	}
	
	@ManyToOne(cascade = CascadeType.MERGE)
	@JoinColumn(name = "applicationChannelId", nullable=true)
	@JsonIgnore
	public ApplicationChannel getApplicationChannel() {
		return applicationChannel;
	}

	public void setApplicationChannel(ApplicationChannel applicationChannel) {
		this.applicationChannel = applicationChannel;
	}
	
	@Column(length = 128, nullable = true)
	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	@Column(length = 128, nullable = true)
	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	@Column(length = 128, nullable = true)
	public String getUrlPath() {
		return urlPath;
	}

	public void setUrlPath(String urlPath) {
		this.urlPath = urlPath;
	}

	@Column(length = 128, nullable = true)
	public String getUrlText() {
		return urlText;
	}

	public void setUrlText(String urlText) {
		this.urlText = urlText;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable = false)
    @JsonIgnore // TODO figure out a better adapter for this
	public Date getModifiedDate() {
		return modifiedDate;
	}

	public void setModifiedDate(Date modifiedDate) {
		this.modifiedDate = modifiedDate;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable = false)
    @JsonIgnore // TODO figure out a better adapter for this
	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	@Temporal(TemporalType.TIMESTAMP)
    @JsonIgnore // TODO figure out a better adapter for this
	public Date getEndDate() {
		return endDate;
	}

	public void setEndDate(Date endDate) {
		this.endDate = endDate;
	}

	@Column(nullable = false)
	public Boolean isOpen() {
		return open;
	}

	public void setOpen(boolean open) {
		this.open = open;
	}

	@Column(nullable = false)
	public boolean getHasStartedProcessing() {
		return startedProcessing;
	}

	public void setHasStartedProcessing(boolean startedProcessing) {
		this.startedProcessing = startedProcessing;
	}
}
