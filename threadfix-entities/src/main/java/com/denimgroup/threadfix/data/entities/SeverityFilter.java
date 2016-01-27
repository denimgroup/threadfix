////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.interfaces.MultiLevelFilter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import javax.persistence.*;

@Entity
@Table(name = "SeverityFilter")
public class SeverityFilter extends BaseEntity implements MultiLevelFilter {

	private static final long serialVersionUID = -203648283130654134L;

	private boolean
		showInfo = true,
		showLow = true,
		showMedium = true,
		showHigh = true,
		showCritical = true,
		global = true,
		enabled = false;

	@Override
	public String toString() {
		return "SeverityFilter [showInfo=" + showInfo + ", showLow=" + showLow
				+ ", showMedium=" + showMedium + ", showHigh=" + showHigh
				+ ", showCritical=" + showCritical + ", global=" + global
				+ ", application=" + application + ", organization="
				+ organization + "]";
	}

	private Application application = null;
	private Organization organization = null;
	
	public void setFilters(SeverityFilter other) {
		if (other == null) {
			setFilters(new SeverityFilter());
		} else {
			this.showInfo = other.showInfo;
			this.showLow = other.showLow;
			this.showMedium = other.showMedium;
			this.showHigh = other.showHigh;
			this.showCritical = other.showCritical;
		}
	}
	
	@Transient
	public boolean shouldHide(GenericSeverity genericSeverity) {
		boolean result = false;
		if (genericSeverity != null && genericSeverity.getName() != null) {
			String name = genericSeverity.getName();
            if (name.equals(GenericSeverity.CRITICAL)) {
                result = !showCritical;
            } else if (name.equals(GenericSeverity.HIGH)) {
                result = !showHigh;
            } else if (name.equals(GenericSeverity.MEDIUM)) {
                result = !showMedium;
            } else if (name.equals(GenericSeverity.LOW)) {
                result = !showLow;
            } else if (name.equals(GenericSeverity.INFO)) {
                result = !showInfo;
            }
		}
		return result;
	}

	@ManyToOne
    @JsonIgnore
	@JoinColumn(name = "applicationId")
	public Application getApplication() {
		return application;
	}

	public void setApplication(Application application) {
		this.application = application;
	}

	@ManyToOne
    @JsonIgnore
	@JoinColumn(name = "organizationId")
	public Organization getOrganization() {
		return organization;
	}

	public void setOrganization(Organization organization) {
		this.organization = organization;
	}
	
	@Column(nullable = false)
	@JsonView(Object.class)
	public boolean getEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	@Column(nullable = false)
	@JsonView(Object.class)
	public boolean getGlobal() {
		return global;
	}

	public void setGlobal(boolean global) {
		this.global = global;
	}

	@Column(nullable = false)
	@JsonView(Object.class)
	public boolean getShowInfo() {
		return showInfo;
	}

	public void setShowInfo(boolean showInfo) {
		this.showInfo = showInfo;
	}

	@Column(nullable = false)
	@JsonView(Object.class)
	public boolean getShowLow() {
		return showLow;
	}

	public void setShowLow(boolean showLow) {
		this.showLow = showLow;
	}

	@JsonView(Object.class)
	@Column(nullable = false)
	public boolean getShowMedium() {
		return showMedium;
	}

	public void setShowMedium(boolean showMedium) {
		this.showMedium = showMedium;
	}

	@Column(nullable = false)
	@JsonView(Object.class)
	public boolean getShowHigh() {
		return showHigh;
	}

	public void setShowHigh(boolean showHigh) {
		this.showHigh = showHigh;
	}

	@Column(nullable = false)
	@JsonView(Object.class)
	public boolean getShowCritical() {
		return showCritical;
	}

	public void setShowCritical(boolean showCritical) {
		this.showCritical = showCritical;
	}
}
