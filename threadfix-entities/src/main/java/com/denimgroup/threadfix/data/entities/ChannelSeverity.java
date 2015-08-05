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

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "ChannelSeverity")
public class ChannelSeverity extends BaseEntity {

	private static final long serialVersionUID = -5149330788304148078L;

	private ChannelType channelType;
	private String name;
	private String code;
	private int numericValue;
	private SeverityMap severityMap;

	private List<Finding> findings;

	@ManyToOne
	@JoinColumn(name = "channelTypeId")
	@JsonIgnore
	public ChannelType getChannelType() {
		return channelType;
	}

	public void setChannelType(ChannelType channelType) {
		this.channelType = channelType;
	}

	@Column(length = 25, nullable = false)
    @JsonView(Object.class)
    public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(length = 25, nullable = false)
	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	@OneToOne(mappedBy = "channelSeverity")
	@JsonView({AllViews.TableRow.class, AllViews.VulnerabilityDetail.class})
	public SeverityMap getSeverityMap() {
		return severityMap;
	}

	public void setSeverityMap(SeverityMap severityMap) {
		this.severityMap = severityMap;
	}

	@OneToMany(mappedBy = "channelSeverity")
	@JsonIgnore
	public List<Finding> getFindings() {
		return findings;
	}

	public void setFindings(List<Finding> findings) {
		this.findings = findings;
	}

    @JsonView({ AllViews.TableRow.class, AllViews.VulnerabilityDetail.class })
	public int getNumericValue() {
		return numericValue;
	}

	public void setNumericValue(int numericValue) {
		this.numericValue = numericValue;
	}

    @Override
    public String toString() {
        return "ChannelSeverity{" +
                "name='" + name + '\'' +
                '}';
    }
}
