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
import org.hibernate.annotations.Cascade;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

/**
 * This class is used in place of saving repeat Findings for subsequent scans,
 * so that the data is still there when it's needed for reports.
 * 
 * It maps scans to Findings from other scans from the same channel. Since the
 * finding-level maps are made based on the native ID, they can not be cross-channel.
 * 
 * @author mcollins
 *
 */
@Entity
@Table(name = "ScanRepeatFindingMap")
public class ScanRepeatFindingMap extends BaseEntity implements FindingLike {

	private static final long serialVersionUID = 6597715847823368634L;

	private Finding finding;
	private Scan scan;
	private List<StatisticsCounter> statisticsCounters;
	
	/**
	 * This constructor is here because Spring demanded it and should not be used.
	 *
	 */
	public ScanRepeatFindingMap(){}
	
	/**
	 * This constructor maps everything correctly, so just creating the object is enough.
	 * This object is useless without the mappings, so it makes sense to include them here.
	 * @param finding
	 * @param scan
	 */
	public ScanRepeatFindingMap(Finding finding, Scan scan) {
		this.finding = finding;
		this.scan = scan;
		
		if (finding != null) {
			if (finding.getScanRepeatFindingMaps() == null) {
				finding.setScanRepeatFindingMaps(new ArrayList<ScanRepeatFindingMap>());
			}
			finding.getScanRepeatFindingMaps().add(this);
		}
		
		if (scan != null) {
			if (scan.getScanRepeatFindingMaps() == null) {
				scan.setScanRepeatFindingMaps(new ArrayList<ScanRepeatFindingMap>());
			}
			scan.getScanRepeatFindingMaps().add(this);
		}
	}

	@ManyToOne
	@JoinColumn(name = "findingId")
	public Finding getFinding() {
		return finding;
	}

	public void setFinding(Finding finding) {
		this.finding = finding;
	}

	@Override
	@Transient
	public Vulnerability getVulnerability() {
		if (finding != null && finding.getVulnerability() != null) {
			return finding.getVulnerability();
		} else {
			return null;
		}
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

	@OneToMany(mappedBy = "scanRepeatFindingMap")
	@Cascade({ org.hibernate.annotations.CascadeType.ALL })
	@JsonIgnore
	public List<StatisticsCounter> getStatisticsCounters() {
		return statisticsCounters;
	}

	public void setStatisticsCounters(List<StatisticsCounter> statisticsCounters) {
		this.statisticsCounters = statisticsCounters;
	}
}
