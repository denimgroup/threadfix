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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.Size;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.hibernate.validator.constraints.NotEmpty;

@Entity
@Table(name = "GenericSeverity")
public class GenericSeverity extends BaseEntity {

	private static final long serialVersionUID = 8187838743225832281L;
	
	public static final String INFO = "Info";
	public static final String LOW = "Low";
	public static final String MEDIUM = "Medium";
	public static final String HIGH = "High";
	public static final String CRITICAL = "Critical";
	
	/**
	 * This field is helpful when you need to compare severities numerically.
	 */
	public static final Map<String, Integer> NUMERIC_MAP = new HashMap<>();
	static {
		NUMERIC_MAP.put(INFO, 1);
		NUMERIC_MAP.put(LOW, 2);
		NUMERIC_MAP.put(MEDIUM, 3);
		NUMERIC_MAP.put(HIGH, 4);
		NUMERIC_MAP.put(CRITICAL, 5);
	}

	@NotEmpty(message = "{errors.required}")
	@Size(max = 50, message = "{errors.maxlength}")
	private String name;
	
	private Integer intValue;

	private List<SeverityMap> severityMapping;
	private List<Vulnerability> vulnerabilities;

	@Column(length = 50, nullable = false)
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
}
