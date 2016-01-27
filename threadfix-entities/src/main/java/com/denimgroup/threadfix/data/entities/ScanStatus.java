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
import org.hibernate.annotations.Type;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name="ScanStatus")
public class ScanStatus extends AuditableEntity {

	private static final long serialVersionUID = 3437557929384543428L;
	private ScanQueueTask scanQueueTask;
	private Date timestamp;
	private String message;

	@ManyToOne
	@JoinColumn(name = "scanQueueTaskId")
	@JsonIgnore
	public ScanQueueTask getScanQueueTask() {
		return scanQueueTask;
	}

	public void setScanQueueTask(ScanQueueTask scanQueueTask) {
		this.scanQueueTask = scanQueueTask;
	}

	@Temporal(TemporalType.TIMESTAMP)
	@Column(nullable = false)
    @JsonIgnore
	public Date getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Date timestamp) {
		this.timestamp = timestamp;
	}

	@Type(type="text")
	@Column
	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
	
	
}
