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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Comparator;
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
import javax.persistence.Transient;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;

import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;

@Entity
@Table(name = "Scan")
public class Scan extends BaseEntity {

	private static final long serialVersionUID = -8461350611851383656L;

	private ApplicationChannel applicationChannel;
	private Calendar importTime;
	private Application application;
	private Integer numberClosedVulnerabilities;
	private Integer numberNewVulnerabilities;
	private Integer numberOldVulnerabilities;
	private Integer numberResurfacedVulnerabilities;
	private Integer numberTotalVulnerabilities;
	private Integer numberHiddenVulnerabilities;
	private Integer numberRepeatResults;
	private Integer numberRepeatFindings;
	
	private Long numberInfoVulnerabilities = 0L, numberLowVulnerabilities = 0L,
			numberMediumVulnerabilities = 0L, numberHighVulnerabilities = 0L,
			numberCriticalVulnerabilities = 0L;
	
	private User user;
	
	private List<ScanRepeatFindingMap> scanRepeatFindingMaps;
	private List<ScanReopenVulnerabilityMap> scanReopenVulnerabilityMaps;
	private List<ScanCloseVulnerabilityMap> scanCloseVulnerabilityMaps;
	
	// TODO probably rename this - it's for the graphs
	private Integer numberOldVulnerabilitiesInitiallyFromThisChannel;

	private List<Finding> findings;
	
	private Integer numWithoutChannelVulns = null;
	private Integer numWithoutGenericMappings = null;
	
	private Integer totalNumberSkippedResults = null;
	private Integer totalNumberFindingsMergedInScan = null;
	
	// These are for determining what type of scanner was used
	private static final List<String> DYNAMIC_TYPES = Arrays.asList(
            ScannerType.ACUNETIX_WVS.getFullName(),
            ScannerType.APPSCAN_ENTERPRISE.getFullName(),
            ScannerType.ARACHNI.getFullName(),
            ScannerType.BURPSUITE.getFullName(),
            ScannerType.NESSUS.getFullName(),
            ScannerType.NETSPARKER.getFullName(),
            ScannerType.NTO_SPIDER.getFullName(),
            ScannerType.SKIPFISH.getFullName(),
            ScannerType.W3AF.getFullName(),
            ScannerType.WEBINSPECT.getFullName(),
            ScannerType.ZAPROXY.getFullName(),
            ScannerType.QUALYSGUARD_WAS.getFullName(),
            ScannerType.APPSCAN_DYNAMIC.getFullName());
	
	private static final List<String> STATIC_TYPES = Arrays.asList(
            ScannerType.APPSCAN_SOURCE.getFullName(),
            ScannerType.FINDBUGS.getFullName(),
            ScannerType.FORTIFY.getFullName(),
            ScannerType.VERACODE.getFullName(),
            ScannerType.CAT_NET.getFullName(),
            ScannerType.BRAKEMAN.getFullName());
	private static final List<String> MIXED_TYPES = Arrays.asList(ScannerType.SENTINEL.getFullName());
	private static final String DYNAMIC="Dynamic", STATIC="Static", MIXED="Mixed";
	
	@Size(max = 255, message = "{errors.maxlength} 255.")
	private String filePathRoot;
	@Size(max = 255, message = "{errors.maxlength} 255.")
	private String urlPathRoot;
	
	@ManyToOne(cascade = CascadeType.MERGE)
	@JoinColumn(name = "applicationChannelId")
	@JsonIgnore
	public ApplicationChannel getApplicationChannel() {
		return applicationChannel;
	}

	public void setApplicationChannel(ApplicationChannel applicationChannel) {
		this.applicationChannel = applicationChannel;
	}

	@Temporal(TemporalType.TIMESTAMP)
	public Calendar getImportTime() {
		return importTime;
	}

	public void setImportTime(Calendar importTime) {
		this.importTime = importTime;
	}

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
	@JoinColumn(nullable = true, name = "userId")
	@JsonIgnore
	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
	public List<Finding> getFindings() {
		return findings;
	}

	public void setFindings(List<Finding> findings) {
		this.findings = findings;
	}
	
	@Column(length = 256)
	public String getFilePathRoot() {
		return filePathRoot;
	}

	public void setFilePathRoot(String filePathRoot) {
		this.filePathRoot = filePathRoot;
	}

	@Column(length = 256)
	public String getUrlPathRoot() {
		return urlPathRoot;
	}

	public void setUrlPathRoot(String urlPathRoot) {
		this.urlPathRoot = urlPathRoot;
	}
	
	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
	public List<ScanRepeatFindingMap> getScanRepeatFindingMaps() {
		return scanRepeatFindingMaps;
	}

	public void setScanRepeatFindingMaps(List<ScanRepeatFindingMap> scanRepeatFindingMaps) {
		this.scanRepeatFindingMaps = scanRepeatFindingMaps;
	}
	
	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
	public List<ScanReopenVulnerabilityMap> getScanReopenVulnerabilityMaps() {
		return scanReopenVulnerabilityMaps;
	}

	public void setScanReopenVulnerabilityMaps(List<ScanReopenVulnerabilityMap> ScanReopenVulnerabilityMaps) {
		this.scanReopenVulnerabilityMaps = ScanReopenVulnerabilityMaps;
	}
	
	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
	public List<ScanCloseVulnerabilityMap> getScanCloseVulnerabilityMaps() {
		return scanCloseVulnerabilityMaps;
	}

	public void setScanCloseVulnerabilityMaps(List<ScanCloseVulnerabilityMap> ScanCloseVulnerabilityMaps) {
		this.scanCloseVulnerabilityMaps = ScanCloseVulnerabilityMaps;
	}

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
	@Column
	public Integer getNumberOldVulnerabilitiesInitiallyFromThisChannel() {
		return numberOldVulnerabilitiesInitiallyFromThisChannel;
	}

	public void setNumberOldVulnerabilitiesInitiallyFromThisChannel(
			Integer numberOldVulnerabilitiesInitiallyFromThisChannel) {
		this.numberOldVulnerabilitiesInitiallyFromThisChannel = numberOldVulnerabilitiesInitiallyFromThisChannel;
	}

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
	
	@Transient
	public Integer getNumWithoutGenericMappings() {
		return numWithoutGenericMappings;
	}
	
	public void setNumWithoutGenericMappings(Integer numWithoutGenericMappings) {
		this.numWithoutGenericMappings = numWithoutGenericMappings;
	}

	@Transient
	public Integer getNumWithoutChannelVulns() {
		return numWithoutChannelVulns;
	}
	
	public void setNumWithoutChannelVulns(Integer numWithoutChannelVulns) {
		this.numWithoutChannelVulns = numWithoutChannelVulns;
	}
	
	@Transient
	public Integer getTotalNumberSkippedResults() {
		return totalNumberSkippedResults;
	}
	
	public void setTotalNumberSkippedResults(Integer totalNumberSkippedResults) {
		this.totalNumberSkippedResults = totalNumberSkippedResults;
	}
	
	@Transient
	public Integer getTotalNumberFindingsMergedInScan() {
		return totalNumberFindingsMergedInScan;
	}
	
	public void setTotalNumberFindingsMergedInScan(
			Integer totalNumberFindingsMergedInScan) {
		this.totalNumberFindingsMergedInScan = totalNumberFindingsMergedInScan;
	}

	// These two functions establish the order the integers come in and this
	// order should not be changed.
	@Transient
	@JsonIgnore
	public List<Integer> getReportList() {
		List<Integer> integerList = new ArrayList<>();
		integerList.add(getId());
		integerList.add(getNumberTotalVulnerabilities());
		integerList.add(getNumberNewVulnerabilities());
		integerList.add(getNumberOldVulnerabilities());
		integerList.add(getNumberResurfacedVulnerabilities());
		integerList.add(getNumberClosedVulnerabilities());
		return integerList;
	}
	
	@JsonIgnore
	public static ScanTimeComparator getTimeComparator() {
		return new ScanTimeComparator();
	}

	static public class ScanTimeComparator implements Comparator<Scan> {
	
		@Override
		public int compare(Scan scan1, Scan scan2){
			Calendar scan1Time = scan1.getImportTime();
			Calendar scan2Time = scan2.getImportTime();
			
			if (scan1Time == null || scan2Time == null) {
				return 0;
			}
			
			return scan1Time.compareTo(scan2Time);
		}
	}

	@Column
	public Long getNumberInfoVulnerabilities() {
		return numberInfoVulnerabilities;
	}

	public void setNumberInfoVulnerabilities(Long numberInfoVulnerabilities) {
		this.numberInfoVulnerabilities = numberInfoVulnerabilities;
	}
	
	@Column
	public Long getNumberLowVulnerabilities() {
		return numberLowVulnerabilities;
	}

	public void setNumberLowVulnerabilities(Long numberLowVulnerabilities) {
		this.numberLowVulnerabilities = numberLowVulnerabilities;
	}
	
	@Column
	public Long getNumberMediumVulnerabilities() {
		return numberMediumVulnerabilities;
	}

	public void setNumberMediumVulnerabilities(Long numberMediumVulnerabilities) {
		this.numberMediumVulnerabilities = numberMediumVulnerabilities;
	}
	
	@Column
	public Long getNumberHighVulnerabilities() {
		return numberHighVulnerabilities;
	}

	public void setNumberHighVulnerabilities(Long numberHighVulnerabilities) {
		this.numberHighVulnerabilities = numberHighVulnerabilities;
	}
	
	@Column
	public Long getNumberCriticalVulnerabilities() {
		return numberCriticalVulnerabilities;
	}

	public void setNumberCriticalVulnerabilities(
			Long numberCriticalVulnerabilities) {
		this.numberCriticalVulnerabilities = numberCriticalVulnerabilities;
	}
	
	@Column
	public Integer getNumberHiddenVulnerabilities() {
		if (numberHiddenVulnerabilities == null) {
			return 0;
		} else {
			return numberHiddenVulnerabilities;
		}
	}

	public void setNumberHiddenVulnerabilities(
			Integer numberHiddenVulnerabilities) {
		this.numberHiddenVulnerabilities = numberHiddenVulnerabilities;
	}

	@Transient
	public String getScannerType() {
		if (getApplicationChannel() != null && getApplicationChannel().getChannelType() != null
				&& getApplicationChannel().getChannelType().getName() != null) {
			String scannerName = getApplicationChannel().getChannelType().getName();
			if (DYNAMIC_TYPES.contains(scannerName)) {
				return DYNAMIC;
			} else if (STATIC_TYPES.contains(scannerName)) {
				return STATIC;
			} else if (MIXED_TYPES.contains(scannerName)) {
				return MIXED;
			}
		}

		return null;
	}
	
	@Transient
	public boolean isStatic() {
		return STATIC.equals(getScannerType());
	}
	
	public List<PartialMapping> toPartialMappingList() {
		List<PartialMapping> results = new ArrayList<>();
		
		if (getFindings() != null) {
			for (Finding finding : getFindings()) {
				results.add(finding.toPartialMapping());
			}
		}
		
		return results;
	}
}
