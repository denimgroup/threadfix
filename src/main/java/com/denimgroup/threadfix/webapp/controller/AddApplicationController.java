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

import java.util.List;

import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/organizations/{orgId}/applications/new")
@SessionAttributes("application")
public class AddApplicationController {

	private OrganizationService organizationService = null;
	private ApplicationService applicationService = null;
	private DefectTrackerService defectTrackerService = null;
	private WafService wafService = null;

	private final Log log = LogFactory.getLog(AddApplicationController.class);
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String[] { "name", "url", "defectTracker.id", "userName", "password", "waf.id", "projectName" });
	}
	
	@Autowired
	public AddApplicationController(OrganizationService organizationService,
			ApplicationService applicationService,
			DefectTrackerService defectTrackerService,
			WafService wafService) {
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.defectTrackerService = defectTrackerService;
		this.wafService = wafService;
	}

	@ModelAttribute
	public List<DefectTracker> populateDefectTrackers() {
		return defectTrackerService.loadAllDefectTrackers();
	}

	@ModelAttribute
	public List<Waf> populateWafs() {
		return wafService.loadAll();
	}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String newForm(@PathVariable("orgId") int orgId, Model model) {
		Organization organization = organizationService.loadOrganization(orgId);
		if (organization != null) {
			Application application = new Application();
			application.setOrganization(organization);
			model.addAttribute(application);
			return "applications/form";
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
		}
	}

	@RequestMapping(method = RequestMethod.POST)
	public String newSubmit(@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application, BindingResult result,
			SessionStatus status) {
		
		if (application.getName() != null && application.getName().trim().equals("")
				&& !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}
		
		if (result.hasErrors()) {
			return "applications/form";
		} else {
			Application databaseApplication = applicationService.loadApplication(application.getName().trim());
			if (databaseApplication != null)
				result.rejectValue("name", "errors.nameTaken");

			if (application.getWaf() != null && application.getWaf().getId() == 0)
				application.setWaf(null);
			
			if (application.getWaf() != null && (application.getWaf().getId() == null  
					|| wafService.loadWaf(application.getWaf().getId()) == null))
				result.rejectValue("waf.id", "errors.invalid", new String [] { "WAF Choice" }, null);

			applicationService.validateApplicationDefectTracker(application, result);
			
			if (result.hasErrors())
				return "applications/form";

			applicationService.storeApplication(application);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug("User " + user + " has created an Application with the name " + application.getName() +
					", the ID " + application.getId() +
					", and the Organization " + application.getOrganization().getName());
			
			status.setComplete();
			return "redirect:/organizations/" + String.valueOf(orgId) + "/applications/" + application.getId();
		}
	}
}
