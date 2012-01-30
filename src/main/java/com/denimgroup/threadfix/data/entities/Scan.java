////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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
import java.util.Calendar;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

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

import org.codehaus.jackson.annotate.JsonIgnore;

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
	private Integer numberRepeatResults;
	private Integer numberRepeatFindings;

	private List<Finding> findings;
	
	// The rest of the variables are just caches for the scan display page
	private List<Finding> mappedFindings = null;
	private List<Finding> unmappedFindings = null;
	
	private Integer numWithoutChannelVulns = null;
	private Integer numWithoutGenericMappings = null;
	
	private Integer totalNumberSkippedResults = null;
	private Integer totalNumberFindingsMergedInScan = null;
	
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

	@OneToMany(mappedBy = "scan", cascade = CascadeType.ALL)
	public List<Finding> getFindings() {
		return findings;
	}

	public void setFindings(List<Finding> findings) {
		this.findings = findings;
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
	@JsonIgnore
	public List<Finding> getUnmappedFindings() {
		if (unmappedFindings == null) {
			generateFindingLists();
		}
		return unmappedFindings;
	}
	
	@Transient
	@JsonIgnore
	public List<Finding> getMappedFindings() {
		if (mappedFindings == null) {
			generateFindingLists();
		}
		return mappedFindings;
	}
	
	@Transient
	public Integer getNumWithoutGenericMappings() {
		if (numWithoutGenericMappings == null)
			generateFindingLists();
		return numWithoutGenericMappings;
	}
	
	@Transient
	public Integer getNumWithoutChannelVulns() {
		if (numWithoutChannelVulns == null)
			generateFindingLists();
		return numWithoutChannelVulns;
	}
	
	@Transient
	public Integer getTotalNumberSkippedResults() {
		if (totalNumberSkippedResults == null)
			generateFindingLists();
		return totalNumberSkippedResults;
	}
	
	@Transient
	public Integer getTotalNumberFindingsMergedInScan() {
		if (totalNumberFindingsMergedInScan == null)
			generateFindingLists();
		return totalNumberFindingsMergedInScan;
	}
	
	// This method calculates the scan information for the scan view page
	@Transient
	private void generateFindingLists() {
		unmappedFindings = new ArrayList<Finding>();
		mappedFindings = new ArrayList<Finding>();
		numWithoutChannelVulns = 0;
		numWithoutGenericMappings = 0;
		totalNumberSkippedResults = 0;
		totalNumberFindingsMergedInScan = 0;
		
		Set<Integer> vulnIdSet = new TreeSet<Integer>();
		
		if (getFindings() == null || getFindings().size() == 0)
			return;
		
		for (Finding finding : getFindings()) {
			if (finding == null)
				continue;
			
			totalNumberSkippedResults += finding.getNumberMergedResults() - 1;
			
			if (finding.getVulnerability() == null) {
				unmappedFindings.add(finding);
				
				if (finding.getChannelVulnerability() == null) {
					numWithoutChannelVulns++;
				} else if (finding.getChannelVulnerability().getVulnerabilityMaps() == null ||
						finding.getChannelVulnerability().getVulnerabilityMaps().size() == 0) {
					numWithoutGenericMappings++;
				}
			} else {
				mappedFindings.add(finding);
				if (vulnIdSet.contains(finding.getVulnerability().getId())) {
					totalNumberFindingsMergedInScan++;
				} else {
					vulnIdSet.add(finding.getVulnerability().getId());
				}
			}
		}
	}

	// These two functions establish the order the integers come in and this
	// order should not be changed.
	@Transient
	@JsonIgnore
	public List<Integer> getReportList() {
		List<Integer> integerList = new ArrayList<Integer>();
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
	
		public int compare(Scan scan1, Scan scan2){
			Calendar scan1Time = scan1.getImportTime();
			Calendar scan2Time = scan2.getImportTime();
			
			if (scan1Time == null || scan2Time == null) 
				return 0;
			
			return scan1Time.compareTo(scan2Time);
		}
	}

}
