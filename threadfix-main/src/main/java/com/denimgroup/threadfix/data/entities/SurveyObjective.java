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

import javax.persistence.Basic;
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
@Table(name = "SurveyObjective")
public class SurveyObjective extends BaseEntity {

	private static final long serialVersionUID = 1397612826891950090L;

	private int level;
	private String description;
	private SurveyPractice surveyPractice;

	private List<SurveyQuestion> questions = new ArrayList<>();

	@Override
	public void setId(Integer id) {
		// TODO There is a better way to do this
		super.setId(id);
		for (SurveyQuestion question : questions) {
			question.setSurveyObjective(this);
		}
	}

	@Basic
	public int getLevelNumber() {
		return level;
	}

	public void setLevelNumber(int level) {
		this.level = level;
	}

	@Column(length = 1024)
	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	@ManyToOne
	@JoinColumn(name = "surveyPracticeId")
	@JsonIgnore
	public SurveyPractice getSurveyPractice() {
		return surveyPractice;
	}

	public void setSurveyPractice(SurveyPractice surveyPractice) {
		this.surveyPractice = surveyPractice;
	}

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "surveyObjective")
	public List<SurveyQuestion> getSurveyQuestions() {
		return questions;
	}

	public void setSurveyQuestions(List<SurveyQuestion> questions) {
		this.questions = questions;
	}

}
