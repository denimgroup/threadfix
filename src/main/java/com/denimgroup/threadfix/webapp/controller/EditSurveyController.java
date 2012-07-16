////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.webapp.controller;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.SurveyAnswer;
import com.denimgroup.threadfix.data.entities.SurveyRanking;
import com.denimgroup.threadfix.data.entities.SurveyResult;
import com.denimgroup.threadfix.service.SurveyService;

@Controller
@RequestMapping("/organizations/{orgId}/surveys/{resultId}/edit")
@SessionAttributes("surveyResult")
public class EditSurveyController {

	private SurveyService surveyService = null;
	
	private final Log log = LogFactory.getLog(EditSurveyController.class);

	@Autowired
	public EditSurveyController(SurveyService surveyService) {
		this.surveyService = surveyService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView setupForm(@PathVariable("orgId") int orgId,
			@PathVariable("resultId") int resultId) {
		SurveyResult surveyResult = surveyService.loadSurveyResult(resultId);
		
		if (surveyResult == null) {
			log.warn(ResourceNotFoundException.getLogMessage("SurveyResult", resultId));
			throw new ResourceNotFoundException();
		}
		
		ModelAndView mav = new ModelAndView("surveys/form");
		mav.addObject(surveyResult);
		return mav;
	}

	@RequestMapping(params = "surveys/save", method = RequestMethod.POST)
	public String saveResults(@PathVariable("orgId") int orgId,
			@ModelAttribute SurveyResult surveyResult, ModelMap model) {
		if (surveyResult.isSubmitted()) {
			log.error("Cannot save already submitted survey");
			return "redirect:/organizations/" + orgId + "/surveys/" + surveyResult.getId();
		}

		if (surveyResult.getSurveyAnswers() != null) {
			for (SurveyAnswer answer : surveyResult.getSurveyAnswers()) {
				answer.setSurveyResult(surveyResult);
			}
		}

		if (surveyResult.getSurveyRankings() != null) {
			for (SurveyRanking ranking : surveyResult.getSurveyRankings()) {
				ranking.setSurveyResult(surveyResult);
			}
		}

		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		surveyResult.setUser(userName);
		surveyService.saveOrUpdateResult(surveyResult);

		model.addAttribute("saveConfirm", true);
		return "surveys/form";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String submitResults(@PathVariable("orgId") int orgId,
			@ModelAttribute SurveyResult surveyResult, Model model) {
		if (surveyResult.isSubmitted()) {
			log.error("Cannot save already submitted survey");
			return "redirect:/organizations/" + orgId + "/surveys/" + surveyResult.getId();
		}

		surveyResult.calculateRankings();
		surveyService.saveOrUpdateResult(surveyResult);

		return "redirect:/organizations/" + String.valueOf(orgId);
	}
}
