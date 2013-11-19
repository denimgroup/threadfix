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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.codehaus.jackson.annotate.JsonIgnore;

@Entity
@Table(name = "SurveyPractice")
public class SurveyPractice extends BaseEntity {

	private static final long serialVersionUID = -6012905779585545973L;

	private String name;
	private SurveySection surveySection;
	private SurveyRanking surveyRanking;

	private List<SurveyObjective> objectives = new ArrayList<>();

	@Override
	public void setId(Integer id) {
		// TODO There is a better way to do this
		super.setId(id);
		for (SurveyObjective objective : objectives) {
			objective.setSurveyPractice(this);
		}
	}

	@Column(length = 255)
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@ManyToOne
	@JoinColumn(name = "surveySectionId")
	@JsonIgnore
	public SurveySection getSurveySection() {
		return surveySection;
	}

	public void setSurveySection(SurveySection surveySection) {
		this.surveySection = surveySection;
	}

	@OneToOne
	@JoinColumn(name = "surveyRankingId")
	@JsonIgnore
	public SurveyRanking getSurveyRanking() {
		return surveyRanking;
	}

	public void setSurveyRanking(SurveyRanking surveyRanking) {
		this.surveyRanking = surveyRanking;
	}

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "surveyPractice")
	public List<SurveyObjective> getSurveyObjectives() {
		return objectives;
	}

	public void setSurveyObjectives(List<SurveyObjective> objectives) {
		this.objectives = objectives;
	}

	@Transient
	public Map<Integer, SurveyObjective> getObjectivesMap() {
		HashMap<Integer, SurveyObjective> map = new HashMap<>();

		for (SurveyObjective objective : getSurveyObjectives()) {
			map.put(objective.getLevelNumber(), objective);
		}

		return map;
	}
}
