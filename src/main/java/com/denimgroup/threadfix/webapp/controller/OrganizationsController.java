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
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.queue.QueueSender;

/**
 * @author bbeverly
 * 
 */
@Controller
@RequestMapping("/organizations")
public class OrganizationsController {
	
	private final Log log = LogFactory.getLog(OrganizationsController.class);

	private OrganizationService organizationService = null;
	private QueueSender queueSender;
	private ChannelTypeService channelTypeService;
	
	@Autowired
	public OrganizationsController(OrganizationService organizationService,
			QueueSender queueSender, ChannelTypeService channelTypeService) {
		this.organizationService = organizationService;
		this.queueSender = queueSender;
		this.channelTypeService = channelTypeService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		model.addAttribute(organizationService.loadAllActive());
		return "organizations/index";
	}

	@RequestMapping("/{orgId}")
	public ModelAndView detail(@PathVariable("orgId") int orgId) {
		Organization organization = organizationService.loadOrganization(orgId);
		if (organization != null && organization.isActive()) {
			ModelAndView mav = new ModelAndView("organizations/detail");
			mav.addObject(organization);
			return mav;
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
		}
	}

	@RequestMapping("/{orgId}/delete")
	public String deleteOrg(@PathVariable("orgId") int orgId, SessionStatus status) {
		Organization org = organizationService.loadOrganization(orgId);
		if (org != null) {
			if (org.getApplications() == null || org.getApplications().isEmpty()) {
				organizationService.deleteById(orgId);
				status.setComplete();
				log.info("Organization hard deletion was successful on Organization " + org.getName() + ".");
			} else if (org.isActive()) {
				organizationService.deactivateOrganization(org);
				status.setComplete();
				log.info("Organization soft deletion was successful on Organization " + org.getName() + ".");
			}
			return "redirect:/organizations";
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
		}
	}
}
