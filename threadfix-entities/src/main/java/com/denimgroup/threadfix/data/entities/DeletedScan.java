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

/**
 * 
 * This is a class meant to hold deleted instances of Scan objects.
 * 
 * @see Scan
 * @author mcollins
 *
 */
@Entity
@Table(name = "DeletedScan")
public class DeletedScan extends BaseEntity {
	
	private static final long serialVersionUID = -8363345674341358654L;
	
	private Integer applicationChannelId;
	private Calendar importTime;
	private Integer applicationId, numberNewVulnerabilities,
		numberClosedVulnerabilities, numberOldVulnerabilities,
		numberResurfacedVulnerabilities, numberTotalVulnerabilities,
		numberRepeatResults, numberRepeatFindings,
		numberOldVulnerabilitiesInitiallyFromThisChannel;
	
	public DeletedScan(Scan scan) {
		if (scan != null) {
			if (scan.getApplication() != null) {
				setApplicationId(scan.getApplication().getId());
			}
			
			if (scan.getApplicationChannel() != null) {
				setApplicationChannelId(scan.getApplicationChannel().getId());
			}

			setId(scan.getId());
			setImportTime(scan.getImportTime());
			setNumberClosedVulnerabilities(scan.getNumberClosedVulnerabilities());
			setNumberNewVulnerabilities(scan.getNumberNewVulnerabilities());
			setNumberOldVulnerabilities(scan.getNumberOldVulnerabilities());
			setNumberResurfacedVulnerabilities(scan.getNumberResurfacedVulnerabilities());
			setNumberRepeatResults(scan.getNumberRepeatResults());
			setNumberRepeatFindings(scan.getNumberRepeatFindings());
		}
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
}
