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
@Table(name = "SurveySection")
public class SurveySection extends BaseEntity {

	private static final long serialVersionUID = 2197922032525683637L;

	private String sectionName = "";
	private Survey survey;
	private String color = "#000000";
	private String lightColor = "#CCCCCC";

	private List<SurveyPractice> practices = new ArrayList<>();

	@Override
	public void setId(Integer id) {
		// TODO There is a better way to do this
		super.setId(id);
		for (SurveyPractice practice : practices) {
			practice.setSurveySection(this);
		}
	}

	@Column(length = 255)
	public String getSectionName() {
		return sectionName;
	}

	public void setSectionName(String sectionName) {
		this.sectionName = sectionName;
	}

	@ManyToOne
	@JoinColumn(name = "surveyId")
	@JsonIgnore
	public Survey getSurvey() {
		return survey;
	}

	public void setSurvey(Survey survey) {
		this.survey = survey;
	}

	@Column(length = 7)
	public String getColor() {
		return color;
	}

	public void setColor(String color) {
		this.color = color;
	}

	@Column(length = 7)
	public String getLightColor() {
		return lightColor;
	}

	public void setLightColor(String lightColor) {
		this.lightColor = lightColor;
	}

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "surveySection")
	public List<SurveyPractice> getSurveyPractices() {
		return practices;
	}

	public void setSurveyPractices(List<SurveyPractice> practices) {
		this.practices = practices;
	}
}
