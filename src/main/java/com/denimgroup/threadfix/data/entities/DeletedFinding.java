package com.denimgroup.threadfix.data.entities;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
@Table(name = "DeletedFinding")
public class DeletedFinding extends AuditableEntity {
	
	private static final long serialVersionUID = 5278544549677181952L;

	private Vulnerability vulnerability;
	
	private Integer deletedScanId;
	
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
	
	public DeletedFinding(Finding originalFinding) {
		setSourceFileLocation(originalFinding.getSourceFileLocation());
		setNativeId(originalFinding.getNativeId());
		setIsStatic(originalFinding.getIsStatic());
		setMarkedFalsePositive(originalFinding.isMarkedFalsePositive());
		setUser(originalFinding.getUser());
		setId(originalFinding.getId());
		setChannelSeverity(originalFinding.getChannelSeverity());
		setChannelVulnerability(originalFinding.getChannelVulnerability());
		setDeletedScanId(originalFinding.getScan().getId());
		setLongDescription(originalFinding.getLongDescription());
		
	}

//	private List<DataFlowElement> dataFlowElements;
//	private List<ScanRepeatFindingMap> scanRepeatFindingMaps;

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

//	@OneToMany(mappedBy = "finding")
//	@Cascade( { org.hibernate.annotations.CascadeType.ALL } )
//	@OrderBy("sequence DESC")
//	public List<DataFlowElement> getDataFlowElements() {
//		return dataFlowElements;
//	}
//
//	public void setDataFlowElements(List<DataFlowElement> dataFlowElements) {
//		this.dataFlowElements = dataFlowElements;
//	}

	@Column(nullable = false)
	public boolean getIsStatic() {
		return isStatic;
	}
	
	public void setIsStatic(boolean isStatic) {
		this.isStatic = isStatic;
	}
	
//	@OneToMany(mappedBy = "finding", cascade = CascadeType.ALL)
//	@JsonIgnore
//	public List<ScanRepeatFindingMap> getScanRepeatFindingMaps() {
//		return scanRepeatFindingMaps;
//	}
//
//	public void setScanRepeatFindingMaps(List<ScanRepeatFindingMap> scanRepeatFindingMaps) {
//		this.scanRepeatFindingMaps = scanRepeatFindingMaps;
//	}

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
