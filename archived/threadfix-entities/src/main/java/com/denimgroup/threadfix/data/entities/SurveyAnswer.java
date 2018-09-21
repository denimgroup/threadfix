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

@Entity
@Table(name = "SurveyAnswer")
public class SurveyAnswer extends BaseEntity {

	private static final long serialVersionUID = 820673621074487548L;

	private SurveyQuestion surveyQuestion;
	private SurveyAssertion surveyAssertion;
	private SurveyResult surveyResult;
	private boolean answer = false;
	private String comment = "";

	@OneToOne
	@JoinColumn(name = "surveyQuestionId")
	public SurveyQuestion getSurveyQuestion() {
		return surveyQuestion;
	}

	public void setSurveyQuestion(SurveyQuestion surveyQuestion) {
		this.surveyQuestion = surveyQuestion;
	}

	@OneToOne
	@JoinColumn(name = "surveyAssertionId")
	@JsonIgnore
	public SurveyAssertion getSurveyAssertion() {
		return surveyAssertion;
	}

	public void setSurveyAssertion(SurveyAssertion surveyAssertion) {
		this.surveyAssertion = surveyAssertion;
	}

	@ManyToOne
	@JoinColumn(name = "surveyResultId")
	@JsonIgnore
	public SurveyResult getSurveyResult() {
		return surveyResult;
	}

	public void setSurveyResult(SurveyResult surveyResult) {
		this.surveyResult = surveyResult;
	}

	@Column(nullable = false)
	public boolean isAnswer() {
		return answer;
	}

	public void setAnswer(boolean answer) {
		this.answer = answer;
	}

	@Column(length = 1024)
	public String getComment() {
		return comment;
	}

	public void setComment(String comment) {
		this.comment = comment;
	}

	public static SurveyAnswer createEmptyQuestionAnswer(SurveyQuestion question,
			SurveyResult surveyResult) {
		SurveyAnswer answer = new SurveyAnswer();
		answer.setSurveyQuestion(question);
		answer.setSurveyResult(surveyResult);
		return answer;
	}

	public static SurveyAnswer createEmptyAssertionAnswer(SurveyAssertion assertion,
			SurveyResult surveyResult) {
		SurveyAnswer answer = new SurveyAnswer();
		answer.setSurveyAssertion(assertion);
		answer.setSurveyResult(surveyResult);
		return answer;
	}
}
