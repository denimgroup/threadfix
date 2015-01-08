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
package com.denimgroup.threadfix.service;

import java.io.InputStream;
import java.util.Date;
import java.util.List;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.SurveyDao;
import com.denimgroup.threadfix.data.dao.SurveyResultDao;
import com.denimgroup.threadfix.data.entities.Survey;
import com.denimgroup.threadfix.data.entities.SurveyAssertion;
import com.denimgroup.threadfix.data.entities.SurveyLevel;
import com.denimgroup.threadfix.data.entities.SurveyObjective;
import com.denimgroup.threadfix.data.entities.SurveyPractice;
import com.denimgroup.threadfix.data.entities.SurveyQuestion;
import com.denimgroup.threadfix.data.entities.SurveyResult;
import com.denimgroup.threadfix.data.entities.SurveySection;

@Service
@Transactional(readOnly = false) // used to be true
public class SurveyServiceImpl implements SurveyService {

	private SurveyDao surveyDao;
	private SurveyResultDao surveyResultDao;

	@Autowired
	public SurveyServiceImpl(SurveyDao surveyDao, SurveyResultDao surveyResultDao) {
		this.surveyDao = surveyDao;
		this.surveyResultDao = surveyResultDao;
	}

	@Override
	public List<Survey> loadAll() {
		return surveyDao.retrieveAll();
	}

	@Override
	public Survey loadSurvey(int id) {
		return surveyDao.retrieveById(id);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeSurvey(Survey survey) {
		surveyDao.saveOrUpdate(survey);
	}

	@Override
	@Transactional(readOnly = false)
	public void saveOrUpdateResult(SurveyResult surveyResult) {
		Date today = new Date();
		surveyResult.setModifiedDate(today);
		if (surveyResult.isNew()) {
			surveyResult.setCreatedDate(today);
		}

		surveyResultDao.saveOrUpdate(surveyResult);
	}

	@Override
	public SurveyResult loadSurveyResult(int resultId) {
		return surveyResultDao.retrieveById(resultId);
	}

	@Override
	public Survey constructSurvey(InputStream inputStream) throws DocumentException {
		Document document = null;
		
		document = new SAXReader().read(inputStream);

		Element rootElement = document.getRootElement();
		if (!rootElement.getName().equals("survey")) {
			throw new DocumentException("The root element of the XML document should be 'survey'.");
		}

		return constructSurvey(rootElement);
	}

	private Survey constructSurvey(Element element) {
		Survey survey = new Survey();
		survey.setName(element.elementText("name"));

		for (Object levelElement : element.elements("level")) {
			survey.getSurveyLevels().add(constructLevel((Element) levelElement));
		}

		for (Object sectionElement : element.elements("section")) {
			survey.getSurveySections().add(constructSection((Element) sectionElement));
		}

		// Link Back
		for (SurveyLevel l : survey.getSurveyLevels()) {
			l.setSurvey(survey);
		}

		for (SurveySection s : survey.getSurveySections()) {
			s.setSurvey(survey);
		}

		return survey;
	}

	private SurveyLevel constructLevel(Element levelElement) {
		SurveyLevel level = new SurveyLevel();
		level.setNumber(Integer.parseInt(levelElement.attributeValue("number")));
		level.setDescription(levelElement.getTextTrim());

		return level;
	}

	private SurveySection constructSection(Element sectionElement) {
		SurveySection section = new SurveySection();
		section.setSectionName(sectionElement.attributeValue("name"));
		section.setColor(sectionElement.attributeValue("color"));
		section.setLightColor(sectionElement.attributeValue("lightColor"));

		for (Object practiceElement : sectionElement.elements("practice")) {
			section.getSurveyPractices().add(constructPractice((Element) practiceElement));
		}

		for (SurveyPractice practice : section.getSurveyPractices()) {
			practice.setSurveySection(section);
		}

		return section;
	}

	private SurveyPractice constructPractice(Element practiceElement) {
		SurveyPractice practice = new SurveyPractice();
		practice.setName(practiceElement.attributeValue("name"));

		for (Object objectiveElement : practiceElement.elements("objective")) {
			practice.getSurveyObjectives().add(constructObjective((Element) objectiveElement));
		}

		for (SurveyObjective objective : practice.getSurveyObjectives()) {
			objective.setSurveyPractice(practice);
		}

		return practice;
	}

	private SurveyObjective constructObjective(Element objectiveElement) {
		SurveyObjective objective = new SurveyObjective();
		objective.setDescription(objectiveElement.elementText("description"));
		objective.setLevelNumber(Integer.parseInt(objectiveElement.attributeValue("level")));

		for (Object questionElement : objectiveElement.elements("question")) {
			objective.getSurveyQuestions().add(constructQuestion((Element) questionElement));
		}

		for (SurveyQuestion question : objective.getSurveyQuestions()) {
			question.setSurveyObjective(objective);
		}

		return objective;
	}

	private SurveyQuestion constructQuestion(Element questionElement) {
		SurveyQuestion question = new SurveyQuestion();
		question.setSurveyQuestion(questionElement.getTextTrim());

		for (Object assertionElement : questionElement.elements("assertion")) {
			question.getSurveyAssertions().add(constructAssertion((Element) assertionElement));
		}

		for (SurveyAssertion assertion : question.getSurveyAssertions()) {
			assertion.setSurveyQuestion(question);
		}

		return question;
	}

	private SurveyAssertion constructAssertion(Element assertionElement) {
		SurveyAssertion assertion = new SurveyAssertion();
		assertion.setDescription(assertionElement.getTextTrim());

		return assertion;
	}

}
