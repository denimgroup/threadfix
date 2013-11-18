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
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.codehaus.jackson.annotate.JsonIgnore;

@Entity
@Table(name = "SurveyQuestion")
public class SurveyQuestion extends BaseEntity {

	private static final long serialVersionUID = -9114560554646559224L;

	private String question;
	private SurveyObjective surveyObjective;

	private List<SurveyAssertion> assertions = new ArrayList<>();

	@Override
	public void setId(Integer id) {
		// TODO There is a better way to do this
		super.setId(id);
		for (SurveyAssertion assertion : assertions) {
			assertion.setSurveyQuestion(this);
		}
	}

	@Column(length = 1024)
	public String getSurveyQuestion() {
		return question;
	}

	public void setSurveyQuestion(String question) {
		this.question = question;
	}

	@ManyToOne
	@JoinColumn(name = "surveyObjectiveId")
	@JsonIgnore
	public SurveyObjective getSurveyObjective() {
		return surveyObjective;
	}

	public void setSurveyObjective(SurveyObjective surveyObjective) {
		this.surveyObjective = surveyObjective;
	}

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "surveyQuestion")
	public List<SurveyAssertion> getSurveyAssertions() {
		return assertions;
	}

	public void setSurveyAssertions(List<SurveyAssertion> assertions) {
		this.assertions = assertions;
	}

}
