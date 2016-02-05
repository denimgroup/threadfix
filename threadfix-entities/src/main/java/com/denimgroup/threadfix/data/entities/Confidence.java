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

import static com.denimgroup.threadfix.CollectionUtils.list;


@Entity
@Table(name = "Confidence")
public class Confidence extends AuditableEntity {

	private SharedVulnerability sharedVulnerability;
	private Double frontScore;
	private Double backScore;

	public Confidence(){

	}

	public Confidence(SharedVulnerability sharedVulnerability) {
		this.sharedVulnerability = sharedVulnerability;
	}

	@OneToOne
	@JoinColumn(name = "sharedVulnerability_Id")
	@JsonIgnore
	public SharedVulnerability getSharedVulnerability() {
		return sharedVulnerability;
	}

	public void setSharedVulnerability(SharedVulnerability sharedVulnerability) {
		this.sharedVulnerability = sharedVulnerability;
	}

	@Column
	@JsonView({ AllViews.SharedVulnerabilityView.class })
	public Double getFrontScore() {
		return frontScore;
	}

	public void setFrontScore(Double frontScore) {
		this.frontScore = frontScore;
	}

	@Column
	@JsonView({ AllViews.SharedVulnerabilityView.class })
	public Double getBackScore() {
		return backScore;
	}

	public void setBackScore(Double backScore) {
		this.backScore = backScore;
	}
}
