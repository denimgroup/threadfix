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

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.OrderBy;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.annotations.Cascade;

@Entity
@Table(name = "Finding")
public class Finding extends AuditableEntity {

	private static final long serialVersionUID = 5978786078427181952L;
	
	public static final int LONG_DESCRIPTION_LENGTH = 2047;
	public static final int NATIVE_ID_LENGTH = 50;
	public static final int SOURCE_FILE_LOCATION_LENGTH = 128;
	
	private Vulnerability vulnerability;
	
	private Scan scan;
	
	@Size(max = LONG_DESCRIPTION_LENGTH, message = "{errors.maxlength} " + LONG_DESCRIPTION_LENGTH + ".")
	private String longDescription;

	private ChannelVulnerability channelVulnerability;
	
	@Size(max = NATIVE_ID_LENGTH, message = "{errors.maxlength} " + NATIVE_ID_LENGTH + ".")
	private String nativeId;
	private ChannelSeverity channelSeverity;
	private SurfaceLocation surfaceLocation;
	private StaticPathInformation staticPathInformation;
	
	private int numberMergedResults = 1;
	
	@Size(max = SOURCE_FILE_LOCATION_LENGTH, message = "{errors.maxlength} " + SOURCE_FILE_LOCATION_LENGTH + ".")
	private String sourceFileLocation;
	private boolean isStatic;
	private boolean isFirstFindingForVuln;
	private boolean isMarkedFalsePositive = false;

	private User user;

	private List<DataFlowElement> dataFlowElements;
	private List<ScanRepeatFindingMap> scanRepeatFindingMaps;
	
	private String calculatedUrlPath, calculatedFilePath;

	@ManyToOne
	@JsonIgnore
	@JoinColumn(name = "vulnerabilityId")
	public Vulnerability getVulnerability() {
		return vulnerability;
	}

	public void setVulnerability(Vulnerability vulnerability) {
		this.vulnerability = vulnerability;
	}

	@ManyToOne
	@JoinColumn(name = "scanId")
	@JsonIgnore
	public Scan getScan() {
		return scan;
	}

	public void setScan(Scan scan) {
		this.scan = scan;
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

	@Column(length = NATIVE_ID_LENGTH)
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

	@OneToOne(cascade = CascadeType.ALL)
	@JoinColumn(name = "surfaceLocationId")
	public SurfaceLocation getSurfaceLocation() {
		return surfaceLocation;
	}

	public void setSurfaceLocation(SurfaceLocation surfaceLocation) {
		this.surfaceLocation = surfaceLocation;
	}
	
	@OneToOne(cascade = CascadeType.ALL)
	@JoinColumn(name = "staticPathInformationId")
	public StaticPathInformation getStaticPathInformation() {
		return staticPathInformation;
	}

	public void setStaticPathInformation(StaticPathInformation staticPathInformation) {
		this.staticPathInformation = staticPathInformation;
	}
	
	@OneToMany(mappedBy = "finding")
	@Cascade( { org.hibernate.annotations.CascadeType.ALL } )
	@OrderBy("sequence DESC")
	public List<DataFlowElement> getDataFlowElements() {
		return dataFlowElements;
	}

	public void setDataFlowElements(List<DataFlowElement> dataFlowElements) {
		this.dataFlowElements = dataFlowElements;
	}

	@Column(nullable = false)
	public boolean getIsStatic() {
		return isStatic;
	}
	
	public void setIsStatic(boolean isStatic) {
		this.isStatic = isStatic;
	}
	
	@OneToMany(mappedBy = "finding", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<ScanRepeatFindingMap> getScanRepeatFindingMaps() {
		return scanRepeatFindingMaps;
	}

	public void setScanRepeatFindingMaps(List<ScanRepeatFindingMap> scanRepeatFindingMaps) {
		this.scanRepeatFindingMaps = scanRepeatFindingMaps;
	}

	public String getSourceFileLocation() {
		return sourceFileLocation;
	}

	@Column(length = SOURCE_FILE_LOCATION_LENGTH)
	public void setSourceFileLocation(String sourceFileLocation) {
		this.sourceFileLocation = sourceFileLocation;
	}
	
	@Column
	public String getCalculatedUrlPath() {
		return calculatedUrlPath;
	}

	public void setCalculatedUrlPath(String calculatedUrlPath) {
		this.calculatedUrlPath = calculatedUrlPath;
	}

	@Column
	public String getCalculatedFilePath() {
		return calculatedFilePath;
	}

	public void setCalculatedFilePath(String calculatedFilePath) {
		this.calculatedFilePath = calculatedFilePath;
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
	
	@Column(length = LONG_DESCRIPTION_LENGTH)
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
