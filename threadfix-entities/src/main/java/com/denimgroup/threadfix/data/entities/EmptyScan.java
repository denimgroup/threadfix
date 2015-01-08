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
package com.denimgroup.threadfix.data.entities;

import javax.persistence.*;
import java.util.Calendar;

@Entity
@Table(name = "EmptyScan")
public class EmptyScan extends BaseEntity {

	private static final long serialVersionUID = 1132374579790345759L;
	private String fileName;
	private Calendar dateUploaded;
	private ApplicationChannel applicationChannel;
	private boolean alreadyProcessed;

	@Column(length = 100, nullable = false)
	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getDateUploaded() {
		return dateUploaded;
	}

	public void setDateUploaded(Calendar dateUploaded) {
		this.dateUploaded = dateUploaded;
	}

	@ManyToOne(cascade = CascadeType.MERGE)
	@JoinColumn(name = "applicationChannelId")
	public ApplicationChannel getApplicationChannel() {
		return applicationChannel;
	}

	public void setApplicationChannel(ApplicationChannel applicationChannel) {
		this.applicationChannel = applicationChannel;
	}
	
	@Column(nullable = false)
	public boolean getAlreadyProcessed() {
		return alreadyProcessed;
	}

	public void setAlreadyProcessed(boolean alreadyProcessed) {
		this.alreadyProcessed = alreadyProcessed;
	}
}
