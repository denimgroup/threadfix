///////////////////////////////////////////////////////////////////////////
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
import javax.persistence.Table;
import javax.persistence.Transient;

import org.codehaus.jackson.annotate.JsonIgnore;

@Entity
@Table(name = "SurveyResult")
public class SurveyResult extends AuditableEntity {

	private static final long serialVersionUID = 1693943387505370062L;

	private Organization organization;
	private Survey survey;
	private String user;

	private List<SurveyRanking> rankings = new ArrayList<>();
	private List<SurveyAnswer> answers = new ArrayList<>();

	private Map<Integer, SurveyRanking> practiceRankings;
	private Map<Integer, SurveyAnswer> questionAnswers;
	private Map<Integer, SurveyAnswer> assertionAnswers;

	@Override
	public void setId(Integer id) {
		// TODO There is probably a better way to do this
		super.setId(id);
		for (SurveyAnswer answer : answers) {
			answer.setSurveyResult(this);
		}
		for (SurveyRanking ranking : rankings) {
			ranking.setSurveyResult(this);
		}
	}

	@ManyToOne
	@JoinColumn(name = "organizationId")
	@JsonIgnore
	public Organization getOrganization() {
		return this.organization;
	}

	public void setOrganization(Organization organization) {
		this.organization = organization;
	}

	@ManyToOne
	@JoinColumn(name = "surveyId")
	public Survey getSurvey() {
		return survey;
	}

	public void setSurvey(Survey survey) {
		this.survey = survey;
	}

	@Column(length = 25)
	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "surveyResult")
	public List<SurveyRanking> getSurveyRankings() {
		return rankings;
	}

	public void setSurveyRankings(List<SurveyRanking> rankings) {
		this.rankings = rankings;
		this.practiceRankings = null;
	}

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "surveyResult")
	public List<SurveyAnswer> getSurveyAnswers() {
		return answers;
	}

	public void setSurveyAnswers(List<SurveyAnswer> answers) {
		this.answers = answers;
		this.assertionAnswers = null;
		this.questionAnswers = null;
	}

	@Transient
	public Map<Integer, SurveyRanking> getPracticeRankings() {
		if (practiceRankings == null) {
			practiceRankings = new HashMap<>();

			for (SurveyRanking ranking : getSurveyRankings()) {
				practiceRankings.put(ranking.getSurveyPractice().getId(), ranking);
			}
		}

		return practiceRankings;
	}

	@Transient
	public Map<Integer, SurveyAnswer> getAssertionAnswers() {
		if (assertionAnswers == null) {
			assertionAnswers = new HashMap<>();

			for (SurveyAnswer answer : getSurveyAnswers()) {
				if (answer.getSurveyAssertion() != null && answer.getSurveyAssertion().getId() != 0) {
					assertionAnswers.put(answer.getSurveyAssertion().getId(), answer);
				}
			}
		}

		return assertionAnswers;
	}

	@Transient
	public Map<Integer, SurveyAnswer> getQuestionAnswers() {
		if (questionAnswers == null) {
			questionAnswers = new HashMap<>();

			for (SurveyAnswer answer : getSurveyAnswers()) {
				if (answer.getSurveyQuestion() != null && answer.getSurveyQuestion().getId() != 0) {
					questionAnswers.put(answer.getSurveyQuestion().getId(), answer);
				}
			}
		}

		return questionAnswers;
	}

	@Transient
	public String getStatus() {
		return isSubmitted() ? "Submitted" : "In Progress";
	}

	@Transient
	public boolean isSubmitted() {
		return !getSurveyRankings().isEmpty();
	}

	public void calculateRankings() {
		rankings.clear();

		for (SurveySection section : getSurvey().getSurveySections()) {
			for (SurveyPractice practice : section.getSurveyPractices()) {
				rankings.add(SurveyRanking.calculateRanking(this, practice, getSurvey()
						.getSurveyLevels(), getQuestionAnswers(), getAssertionAnswers()));
			}
		}

		practiceRankings = null;
	}

	public void generateEmptyAnswers() {
		if (survey == null) {
			return;
		}

		answers.clear();

		for (SurveySection section : survey.getSurveySections()) {
			for (SurveyPractice practice : section.getSurveyPractices()) {
				for (SurveyObjective objective : practice.getSurveyObjectives()) {
					for (SurveyQuestion question : objective.getSurveyQuestions()) {
						answers.add(SurveyAnswer.createEmptyQuestionAnswer(question, this));
						for (SurveyAssertion assertion : question.getSurveyAssertions()) {
							answers.add(SurveyAnswer.createEmptyAssertionAnswer(assertion, this));
						}
					}
				}
			}
		}

		questionAnswers = null;
		assertionAnswers = null;
	}
}
