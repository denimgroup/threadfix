package com.denimgroup.threadfix.data.entities;

import java.util.Calendar;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "DeletedScan")
public class DeletedScan extends BaseEntity {
	
	private static final long serialVersionUID = -8363345674341358654L;
	
	private Integer applicationChannelId;
	private Calendar importTime;
	private Integer applicationId;
	private Integer numberClosedVulnerabilities;
	private Integer numberNewVulnerabilities;
	private Integer numberOldVulnerabilities;
	private Integer numberResurfacedVulnerabilities;
	private Integer numberTotalVulnerabilities;
	private Integer numberRepeatResults;
	private Integer numberRepeatFindings;
	
	public DeletedScan(Scan scan) {
		this.setApplicationId(scan.getApplication().getId());
		this.setApplicationChannelId(scan.getApplicationChannel().getId());
		this.setId(scan.getId());
		this.setImportTime(scan.getImportTime());
		this.setNumberClosedVulnerabilities(scan.getNumberClosedVulnerabilities());
		this.setNumberNewVulnerabilities(scan.getNumberNewVulnerabilities());
		this.setNumberOldVulnerabilities(scan.getNumberOldVulnerabilities());
		this.setNumberResurfacedVulnerabilities(scan.getNumberResurfacedVulnerabilities());
		this.setNumberRepeatResults(scan.getNumberRepeatResults());
		this.setNumberRepeatFindings(scan.getNumberRepeatFindings());
	}
	
	@Column
	public Integer getApplicationChannelId() {
		return applicationChannelId;
	}

	public void setApplicationChannelId(Integer applicationChannelId) {
		this.applicationChannelId = applicationChannelId;
	}

	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getImportTime() {
		return importTime;
	}

	public void setImportTime(Calendar importTime) {
		this.importTime = importTime;
	}

	@Column
	public Integer getApplicationId() {
		return applicationId;
	}

	public void setApplicationId(Integer applicationId) {
		this.applicationId = applicationId;
	}
	
//	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
//	public List<Finding> getFindings() {
//		return findings;
//	}
//
//	public void setFindings(List<Finding> findings) {
//		this.findings = findings;
//	}
//	
//	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
//	public List<ScanRepeatFindingMap> getScanRepeatFindingMaps() {
//		return scanRepeatFindingMaps;
//	}
//
//	public void setScanRepeatFindingMaps(List<ScanRepeatFindingMap> scanRepeatFindingMaps) {
//		this.scanRepeatFindingMaps = scanRepeatFindingMaps;
//	}
//	
//	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
//	public List<ScanReopenVulnerabilityMap> getScanReopenVulnerabilityMaps() {
//		return scanReopenVulnerabilityMaps;
//	}
//
//	public void setScanReopenVulnerabilityMaps(List<ScanReopenVulnerabilityMap> ScanReopenVulnerabilityMaps) {
//		this.scanReopenVulnerabilityMaps = ScanReopenVulnerabilityMaps;
//	}
//	
//	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
//	public List<ScanCloseVulnerabilityMap> getScanCloseVulnerabilityMaps() {
//		return scanCloseVulnerabilityMaps;
//	}
//
//	public void setScanCloseVulnerabilityMaps(List<ScanCloseVulnerabilityMap> ScanCloseVulnerabilityMaps) {
//		this.scanCloseVulnerabilityMaps = ScanCloseVulnerabilityMaps;
//	}

	@Column
	public Integer getNumberClosedVulnerabilities() {
		return numberClosedVulnerabilities;
	}

	public void setNumberClosedVulnerabilities(Integer numberClosedVulnerabilities) {
		this.numberClosedVulnerabilities = numberClosedVulnerabilities;
	}

	@Column
	public Integer getNumberNewVulnerabilities() {
		return numberNewVulnerabilities;
	}

	public void setNumberNewVulnerabilities(Integer numberNewVulnerabilities) {
		this.numberNewVulnerabilities = numberNewVulnerabilities;
	}

	@Column
	public Integer getNumberOldVulnerabilities() {
		return numberOldVulnerabilities;
	}

	public void setNumberOldVulnerabilities(Integer numberOldVulnerabilities) {
		this.numberOldVulnerabilities = numberOldVulnerabilities;
	}
	
	/**
	 * Keeping track of this information allows us to produce scans without extensive recalculation, 
	 * because we don't have to track down which application channel we should count a vulnerability for.
	 * 
	 * This may lead to a small bug if a vuln is opened in one channel, then found in another and 
	 * subsequently closed there. This needs to be looked into.
	 * @return
	 */
//	@Column
//	public Integer getNumberOldVulnerabilitiesInitiallyFromThisChannel() {
//		return numberOldVulnerabilitiesInitiallyFromThisChannel;
//	}
//
//	public void setNumberOldVulnerabilitiesInitiallyFromThisChannel(
//			Integer numberOldVulnerabilitiesInitiallyFromThisChannel) {
//		this.numberOldVulnerabilitiesInitiallyFromThisChannel = numberOldVulnerabilitiesInitiallyFromThisChannel;
//	}

	@Column
	public Integer getNumberResurfacedVulnerabilities() {
		return numberResurfacedVulnerabilities;
	}

	public void setNumberResurfacedVulnerabilities(Integer numberResurfacedVulnerabilities) {
		this.numberResurfacedVulnerabilities = numberResurfacedVulnerabilities;
	}

	@Column
	public Integer getNumberTotalVulnerabilities() {
		return numberTotalVulnerabilities;
	}

	public void setNumberTotalVulnerabilities(Integer numberTotalVulnerabilities) {
		this.numberTotalVulnerabilities = numberTotalVulnerabilities;
	}
	
	@Column
	public Integer getNumberRepeatFindings() {
		return numberRepeatFindings;
	}

	public void setNumberRepeatFindings(Integer numberRepeatFindings) {
		this.numberRepeatFindings = numberRepeatFindings;
	}
	
	@Column
	public Integer getNumberRepeatResults() {
		return numberRepeatResults;
	}

	public void setNumberRepeatResults(Integer numberRepeatResults) {
		this.numberRepeatResults = numberRepeatResults;
	}

}
