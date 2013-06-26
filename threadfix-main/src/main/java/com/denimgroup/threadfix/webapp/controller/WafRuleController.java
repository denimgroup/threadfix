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
package com.denimgroup.threadfix.webapp.controller;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.WafRuleService;
import com.denimgroup.threadfix.service.WafService;

@Controller
@RequestMapping("/wafs/{wafId}/rules")
public class WafRuleController {
	
	private final SanitizedLogger log = new SanitizedLogger(WafRuleController.class);

	private WafService wafService = null;
	private WafRuleService wafRuleService = null;

	@Autowired
	public WafRuleController(WafService wafService, WafRuleService wafRuleService) {
		this.wafService = wafService;
		this.wafRuleService = wafRuleService;
	}
	
	public WafRuleController(){}

	@PreAuthorize("hasRole('ROLE_CAN_GENERATE_WAF_RULES')")
	@RequestMapping(method = RequestMethod.POST)
	public String generateWafRulesForApps(@PathVariable("wafId") int wafId, 
			@RequestParam("wafDirective") String wafDirective, ModelMap model) {
		Waf waf = wafService.loadWaf(wafId);
		
		if (waf == null) {
			log.warn(ResourceNotFoundException.getLogMessage("WAF", wafId));
			throw new ResourceNotFoundException();
		}
		
		wafService.generateWafRules(waf, wafDirective);
		model.addAttribute(waf);
		return "redirect:/wafs/" + String.valueOf(wafId);
	}

	@RequestMapping("/{ruleId}")
	public String viewRule(@PathVariable("wafId") int wafId, @PathVariable("ruleId") Integer ruleId, ModelMap model) {
		WafRule wafRule = wafRuleService.loadWafRule(ruleId);
		
		if (wafRule == null) {
			log.warn(ResourceNotFoundException.getLogMessage("WafRule", ruleId));
			throw new ResourceNotFoundException();
		}
		
		if (wafRule.getSecurityEvents() == null)
			wafRule.setSecurityEvents(new ArrayList<SecurityEvent>());
		
		model.addAttribute("numTimesFired", wafRule.getSecurityEvents().size());
		model.addAttribute(wafRule);
		return "wafs/rules/detail";
	}
	
}
