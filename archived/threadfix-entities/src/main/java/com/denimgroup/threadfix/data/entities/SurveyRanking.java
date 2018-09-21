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

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "SurveyRanking")
public class SurveyRanking extends BaseEntity {

	private static final long serialVersionUID = 6874128638315188305L;

	private int level;
	private boolean plus;
	private SurveyPractice surveyPractice;
	private SurveyResult surveyResult;

	@Basic
	public int getLevel() {
		return level;
	}

	public void setLevel(int level) {
		this.level = level;
	}

	@Column(nullable = false)
	public boolean isPlus() {
		return plus;
	}

	public void setPlus(boolean plus) {
		this.plus = plus;
	}

	@OneToOne
	@JoinColumn(name = "surveyPracticeId")
	public SurveyPractice getSurveyPractice() {
		return surveyPractice;
	}

	public void setSurveyPractice(SurveyPractice surveyPractice) {
		this.surveyPractice = surveyPractice;
	}

	@OneToOne
	@JoinColumn(name = "surveyResultId")
	@JsonIgnore
	public SurveyResult getSurveyResult() {
		return surveyResult;
	}

	public void setSurveyResult(SurveyResult surveyResult) {
		this.surveyResult = surveyResult;
	}

	public static SurveyRanking calculateRanking(SurveyResult surveyResult,
			SurveyPractice surveyPractice, List<SurveyLevel> levels,
			Map<Integer, SurveyAnswer> questionAnswers, Map<Integer, SurveyAnswer> assertionAnswers) {

		Iterator<SurveyLevel> levelIterator = levels.iterator();

		boolean meetsLevel = true;
		int metLevel = 0;
		boolean isPlus = false;

		while (meetsLevel && levelIterator.hasNext()) {
			SurveyLevel level = levelIterator.next();
			meetsLevel = doResultsMeetLevel(level.getNumber(), surveyPractice.getObjectivesMap()
					.get(level.getNumber()), questionAnswers, assertionAnswers);
			if (meetsLevel) {
				metLevel = level.getNumber();
			} else {
				isPlus = isResultsPlusForLevel(level.getNumber(), surveyPractice.getObjectivesMap()
						.get(level.getNumber()), questionAnswers, assertionAnswers);
			}
		}

		SurveyRanking ranking = new SurveyRanking();
		ranking.setLevel(metLevel);
		ranking.setPlus(isPlus);
		ranking.setSurveyPractice(surveyPractice);
		ranking.setSurveyResult(surveyResult);

		return ranking;
	}

	private static boolean doResultsMeetLevel(int number, SurveyObjective surveyObjective,
			Map<Integer, SurveyAnswer> questionAnswers, Map<Integer, SurveyAnswer> assertionAnswers) {

		if (surveyObjective.getSurveyQuestions().isEmpty()) {
			return false;
		}

		for (SurveyQuestion question : surveyObjective.getSurveyQuestions()) {
			if (!questionAnswers.get(question.getId()).isAnswer()) {
				return false;
			}
		}

		return true;
	}

	private static boolean isResultsPlusForLevel(int number, SurveyObjective surveyObjective,
			Map<Integer, SurveyAnswer> questionAnswers, Map<Integer, SurveyAnswer> assertionAnswers) {

		for (SurveyQuestion question : surveyObjective.getSurveyQuestions()) {
			if (questionAnswers.get(question.getId()).isAnswer()) {
				return true;
			}
			for (SurveyAssertion assertion : question.getSurveyAssertions()) {
				if (assertionAnswers.get(assertion.getId()).isAnswer()) {
					return true;
				}
			}
		}

		return false;
	}
}
