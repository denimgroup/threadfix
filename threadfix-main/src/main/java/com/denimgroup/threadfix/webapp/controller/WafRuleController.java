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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.WafRuleService;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;

@Controller
@RequestMapping("/wafs/{wafId}")
public class WafRuleController {
	
	private final SanitizedLogger log = new SanitizedLogger(WafRuleController.class);

	private WafService wafService = null;
	private WafRuleService wafRuleService = null;
    @Autowired
    private ApplicationService applicationService;

	@Autowired
	public WafRuleController(WafService wafService, WafRuleService wafRuleService) {
		this.wafService = wafService;
		this.wafRuleService = wafRuleService;
	}
	
	public WafRuleController(){}

	@PreAuthorize("hasRole('ROLE_CAN_GENERATE_WAF_RULES')")
	@RequestMapping(value = "/generateRules/{wafApplicationId}/{wafDirective}", method = RequestMethod.POST)
	public @ResponseBody RestResponse<Map<String, Object>> generateWafRulesForApps(@PathVariable("wafId") int wafId,
			@PathVariable("wafDirective") String wafDirective,
            @PathVariable("wafApplicationId") int wafAppId,
            ModelMap model) {
        Map<String, Object> responseMap = new HashMap<>();
		Waf waf = wafService.loadWaf(wafId);
		
		if (waf == null) {
			log.warn(ResourceNotFoundException.getLogMessage("WAF", wafId));
			throw new ResourceNotFoundException();
		}

        Application application = null;
        if (wafAppId != -1) {
           application = applicationService.loadApplication(wafAppId);
            if (application == null
                    || application.getWaf() == null
                    || application.getWaf().getId() != wafId) {
                return RestResponse.failure("Application is invalid");
            }
        }

        List<WafRule> newWafRuleList = wafService.generateWafRules(waf, wafDirective, application);

        String rulesText = wafService.getRulesText(waf, newWafRuleList);

        if (rulesText == null || rulesText.isEmpty()) {
            return failure("No Rules generated for WAF. It is possible none of the vulnerability types in the applications attached are supported by this WAF.");
        }

        responseMap.put("waf", waf);
        responseMap.put("rulesText", rulesText);
        return RestResponse.success(responseMap);
	}


    @RequestMapping("/rule/{ruleId}")
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

    @JsonView(AllViews.TableRow.class)
	@RequestMapping("/getRules")
    @ResponseBody
    public Object getRules(@PathVariable("wafId") int wafId) {
        Map<String, Object> responseMap = new HashMap<>();

        Waf waf = wafService.loadWaf(wafId);

        WafRuleDirective lastDirective = null;

        if ((waf.getLastWafRuleDirective() != null) && (waf.getWafType().getId().equals(
                waf.getLastWafRuleDirective().getWafType().getId()))) {
            lastDirective = waf.getLastWafRuleDirective();
        } else if (waf.getWafType() != null && waf.getWafType().getWafRuleDirectives() != null
                && waf.getWafType().getWafRuleDirectives().size() >= 1) {
            lastDirective = waf.getWafType().getWafRuleDirectives().get(0);
        }

        String rulesText = wafService.getAllRuleText(waf);
        responseMap.put("waf", waf);
        responseMap.put("rulesText", rulesText);
        responseMap.put("lastDirective", lastDirective);
		return RestResponse.success(responseMap);
	}
	
}
