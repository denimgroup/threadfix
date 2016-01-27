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

import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
@Table(name = "DeletedFinding")
public class DeletedFinding extends AuditableEntity {
	
	private static final long serialVersionUID = 5278544549677181952L;

	private Vulnerability vulnerability;
	
	private Integer deletedScanId;

    @Size(max = Finding.LONG_DESCRIPTION_LENGTH)
	private String longDescription;

	private ChannelVulnerability channelVulnerability;
	
	private String nativeId;
	private ChannelSeverity channelSeverity;
	
	private int numberMergedResults = 1;
	
	private String sourceFileLocation;
	private boolean isStatic;
	private boolean isFirstFindingForVuln;
	private boolean isMarkedFalsePositive = false;

	private User user;

    public DeletedFinding(){}
	
	public DeletedFinding(Finding originalFinding) {
		if (originalFinding != null) {
			setSourceFileLocation(originalFinding.getSourceFileLocation());
			setNativeId(originalFinding.getNativeId());
			setIsStatic(originalFinding.getIsStatic());
			setMarkedFalsePositive(originalFinding.isMarkedFalsePositive());
			setUser(originalFinding.getUser());
			setId(originalFinding.getId());
			setChannelSeverity(originalFinding.getChannelSeverity());
			setChannelVulnerability(originalFinding.getChannelVulnerability());
			setLongDescription(originalFinding.getLongDescription());
		
			if (originalFinding.getScan() != null) {
				setDeletedScanId(originalFinding.getScan().getId());
			}
		}
	}

	@ManyToOne
	@JoinColumn(name = "vulnerabilityId")
	public Vulnerability getVulnerability() {
		return vulnerability;
	}

	public void setVulnerability(Vulnerability vulnerability) {
		this.vulnerability = vulnerability;
	}

	@Column
	public Integer getDeletedScanId() {
		return deletedScanId;
	}

	public void setDeletedScanId(Integer deletedScanId) {
		this.deletedScanId = deletedScanId;
	}

	@ManyToOne
	@JoinColumn(name = "channelVulnerabilityId")
	public ChannelVulnerability getChannelVulnerability() {
		return channelVulnerability;
	}

	public void setChannelVulnerability(
			ChannelVulnerability channelVulnerability) {
		this.channelVulnerability = channelVulnerability;
	}

	@Column(length = Finding.NATIVE_ID_LENGTH)
	public String getNativeId() {
		return nativeId;
	}

	public void setNativeId(String nativeId) {
		this.nativeId = nativeId;
	}

	@ManyToOne
	@JoinColumn(name = "channelSeverityId")
	public ChannelSeverity getChannelSeverity() {
		return channelSeverity;
	}

	public void setChannelSeverity(ChannelSeverity channelSeverity) {
		this.channelSeverity = channelSeverity;
	}

	@Column(nullable = false)
	public boolean getIsStatic() {
		return isStatic;
	}
	
	public void setIsStatic(boolean isStatic) {
		this.isStatic = isStatic;
	}

	public String getSourceFileLocation() {
		return sourceFileLocation;
	}

	@Column(length = Finding.SOURCE_FILE_LOCATION_LENGTH)
	public void setSourceFileLocation(String sourceFileLocation) {
		this.sourceFileLocation = sourceFileLocation;
	}
	
	@Column
	public void setNumberMergedResults(int numMergedResults) {
		this.numberMergedResults = numMergedResults;
	}
	
	@Column
	public int getNumberMergedResults() {
		return numberMergedResults;
	}

	@ManyToOne
	@JoinColumn(name = "userId")
	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}
	
	@Column(length = Finding.LONG_DESCRIPTION_LENGTH)
	public void setLongDescription(String longDescription) {
		this.longDescription = longDescription;
	}

	public String getLongDescription() {
		return longDescription;
	}
	
	@Column(nullable = false)
	public boolean isFirstFindingForVuln() {
		return isFirstFindingForVuln;
	}

	public void setFirstFindingForVuln(boolean isFirstFindingForVuln) {
		this.isFirstFindingForVuln = isFirstFindingForVuln;
	}

	@Column
	public boolean isMarkedFalsePositive() {
		return isMarkedFalsePositive;
	}

	public void setMarkedFalsePositive(boolean isMarkedFalsePositive) {
		this.isMarkedFalsePositive = isMarkedFalsePositive;
	}
}
