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

import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import org.hibernate.validator.constraints.NotEmpty;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

@Entity
@Table(name = "GenericSeverity")
public class GenericSeverity extends BaseEntity implements Comparable<GenericSeverity> {

	private static final long serialVersionUID = 8187838743225832281L;
	
	public static final String INFO = "Info";
	public static final String LOW = "Low";
	public static final String MEDIUM = "Medium";
	public static final String HIGH = "High";
	public static final String CRITICAL = "Critical";
	
	/**
	 * This field is helpful when you need to compare severities numerically.
	 */
	public static final Map<String, Integer> NUMERIC_MAP = map(
		INFO, 1,
		LOW, 2,
		MEDIUM, 3,
		HIGH, 4,
		CRITICAL, 5
	);

	public static final Map<String, String> REVERSE_MAP = map(
			"1", INFO,
			"2", LOW,
			"3", MEDIUM,
			"4", HIGH,
			"5", CRITICAL
	);

	@NotEmpty(message = "{errors.required}")
	@Size(max = 50, message = "{errors.maxlength}")
	private String name;

	private Integer intValue;

	private List<SeverityMap> severityMapping;
	private List<Vulnerability> vulnerabilities;
	private String customName;

	@Column(length = 50, nullable = false)
    @JsonView(Object.class)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@OneToMany(mappedBy = "genericSeverity")
	@JsonIgnore
	public List<SeverityMap> getSeverityMapping() {
		return severityMapping;
	}

	public void setSeverityMapping(List<SeverityMap> severityMapping) {
		this.severityMapping = severityMapping;
	}

	@OneToMany(mappedBy = "genericSeverity", cascade = CascadeType.ALL)
	@JsonIgnore
	public List<Vulnerability> getVulnerabilities() {
		return vulnerabilities;
	}

	public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

	@Column(nullable=false)
    @JsonView(Object.class)
	public Integer getIntValue() {
		return intValue;
	}

	public void setIntValue(Integer intValue) {
		this.intValue = intValue;
	}
	
	@Override
	public String toString() {
		return getName();
	}

	@Column(nullable = true)
	@JsonView({AllViews.TableRow.class, AllViews.ApplicationIndexView.class})
	public void setCustomName(String customName) {
		this.customName = customName;
	}

	public String getCustomName() {
		return customName;
	}

	@JsonView({ AllViews.TableRow.class, AllViews.FormInfo.class,
			AllViews.PolicyPageView.class, AllViews.ApplicationIndexView.class,
			AllViews.RestViewScanStatistic.class, AllViews.ScheduledEmailReportView.class,
			AllViews.UIVulnSearch.class, AllViews.VulnSearchApplications.class })
	@Transient
	public String getDisplayName() {
		return customName == null || customName.trim().length() == 0 ? name : customName;
	}

    /**
     * @param genericSeverity the object to be compared.
     * @return a negative integer, zero, or a positive integer as this object
     * is less than, equal to, or greater than the specified object.
     */
    @Override
    public int compareTo(GenericSeverity genericSeverity) {
        return genericSeverity.getIntValue() - this.getIntValue();
    }
}
