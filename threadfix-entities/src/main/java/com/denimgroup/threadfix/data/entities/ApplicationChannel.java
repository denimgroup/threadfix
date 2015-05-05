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

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.util.Iterator;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.listOf;

@Entity
@Table(name = "ApplicationChannel")
public class ApplicationChannel extends AuditableEntity implements Iterable<Scan> {

	private static final long serialVersionUID = 184587892482641379L;

	private Application application;
	private ChannelType channelType;

	private List<Scan> scanList;
	
	private List<JobStatus> jobStatusList;
	
	private Integer scanCounter;

	@ManyToOne
	@JoinColumn(name = "applicationId")
	@JsonIgnore
	public Application getApplication() {
		return application;
	}

	public void setApplication(Application application) {
		this.application = application;
	}

	@ManyToOne
	@JoinColumn(name = "channelTypeId")
	public ChannelType getChannelType() {
		return channelType;
	}

	public void setChannelType(ChannelType channelType) {
		this.channelType = channelType;
	}
	
	@Column
	public Integer getScanCounter() {
		return scanCounter;
	}

	public void setScanCounter(Integer scanCounter) {
		this.scanCounter = scanCounter;
	}

	@OneToMany(mappedBy = "applicationChannel")
	@JsonIgnore
	public List<Scan> getScanList() {
		return scanList;
	}

	public void setScanList(List<Scan> scanList) {
		this.scanList = scanList;
	}

	@OneToMany(mappedBy = "applicationChannel")
	@JsonIgnore
	public List<JobStatus> getJobStatusList() {
		return jobStatusList;
	}

	public void setJobStatusList(List<JobStatus> jobStatusList) {
		this.jobStatusList = jobStatusList;
	}


    @Transient
    public String getNextFileHandle() {
        if (getScanCounter() == null) {
            setScanCounter(1);
        }

        return "scan-file-" + getId() + "-" + getScanCounter();
    }

    public static boolean matchesFileHandleFormat(String fileName) {
        return fileName.matches("(.*)scan-file-[0-9]+-[0-9]+");
    }

	@Override
	public Iterator<Scan> iterator() {
		return getScanList() == null ? listOf(Scan.class).iterator() : getScanList().iterator();
	}

	@Override
	public String toString() {
		return channelType.getName() + "--" + application.getName();
	}
}
