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
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Controller
@RequestMapping("/wafs")
@SessionAttributes({"newWaf","waf"})
public class WafsController {

    @Autowired
	private WafService wafService;
    @Autowired
    private ApplicationService applicationService;

	private final SanitizedLogger log = new SanitizedLogger(WafsController.class);

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		model.addAttribute("newWaf", new Waf());
		model.addAttribute("waf", new Waf());
		model.addAttribute("wafPage", true);
		return "wafs/index";
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(value = "/map", method = RequestMethod.GET)
	@ResponseBody
	public Object map() {
        Map<String, Object> responseMap = new HashMap<>();

        responseMap.put("wafs", wafService.loadAll());
        responseMap.put("wafTypes", wafService.loadAllWafTypes());

        return RestResponse.success(responseMap);
    }

	@RequestMapping("/{wafId}")
	public ModelAndView detail(@PathVariable("wafId") int wafId,
			HttpServletRequest request) {
		ModelAndView mav = new ModelAndView("wafs/detail");
		Waf waf = wafService.loadWaf(wafId);
		
		if (waf == null) {
			log.warn(ResourceNotFoundException.getLogMessage("WAF", wafId));
			throw new ResourceNotFoundException();
		}
		
		boolean canSeeRules;

		if (waf.getApplications() != null && !waf.getApplications().isEmpty()) {
			canSeeRules = PermissionUtils.canSeeRules(waf);
		} else {
			canSeeRules = true;
		}
		
		mav.addObject("canSeeRules", canSeeRules);
		
		boolean hasApps = false;
		if (waf.getApplications() != null) {
			for (Application application : waf.getApplications()) {
				if (application.isActive()) {
					hasApps = true;
					break;
				}
			}
		}
		mav.addObject("hasApps", hasApps);
		mav.addObject("wafTypeList", wafService.loadAllWafTypes());
		
		if (waf.getApplications() != null && waf.getApplications().size() != 0) {
			boolean globalAccess = PermissionUtils.isAuthorized(Permission.READ_ACCESS, null,null);
			if (globalAccess) {
				mav.addObject("apps", waf.getApplications());
			} else {
				List<Application> apps = list();
				
				Set<Integer> authenticatedAppIds = PermissionUtils.getAuthenticatedAppIds();
				Set<Integer> authenticatedTeamIds = PermissionUtils.getAuthenticatedTeamIds();
				for (Application app : waf.getApplications()) {

                    boolean authenticatedAppId = authenticatedAppIds != null && app != null &&
                            app.getId() != null &&
                            authenticatedAppIds.contains(app.getId());

                    boolean authenticatedTeamId = authenticatedTeamIds != null && app != null &&
                            app.getOrganization() != null &&
                            app.getOrganization().getId() != null &&
                            authenticatedTeamIds.contains(app.getOrganization().getId());

					if (authenticatedAppId || authenticatedTeamId) {
						apps.add(app);
					}
				}
				mav.addObject("apps", apps);
			}
		}
		
		if (canSeeRules) {
			String rulesText = wafService.getAllRuleText(waf);
			mav.addObject("rulesText", rulesText);
            mav.addObject("selectedAppId", -1);
			
			WafRuleDirective lastDirective = null;
			List<WafRuleDirective> directives = null;
			
			if ((waf.getLastWafRuleDirective() != null) && (waf.getWafType().getId().equals(
					waf.getLastWafRuleDirective().getWafType().getId()))) {
				lastDirective = waf.getLastWafRuleDirective();
				directives = waf.getWafType().getWafRuleDirectives();
				directives.remove(lastDirective);
			} else if (waf.getWafType() != null && waf.getWafType().getWafRuleDirectives() != null 
							&& waf.getWafType().getWafRuleDirectives().size() >= 1) {
				lastDirective = waf.getWafType().getWafRuleDirectives().get(0);
				directives = waf.getWafType().getWafRuleDirectives();
				directives.remove(0);
			}
			mav.addObject("lastDirective", lastDirective);
			mav.addObject("directives", directives);
		}

		mav.addObject(waf);
        PermissionUtils.addPermissions(mav, null, null,
                Permission.CAN_MANAGE_WAFS, Permission.CAN_GENERATE_WAF_RULES);
		mav.addObject("successMessage", ControllerUtils.getSuccessMessage(request));
		
		return mav;
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_WAFS')")
	@RequestMapping("/{wafId}/delete")
	@ResponseBody
	public Object deleteWaf(@PathVariable("wafId") int wafId,
			SessionStatus status, HttpServletRequest request, Model model) {
		Waf waf = wafService.loadWaf(wafId);
		boolean canDelete = waf != null && waf.getCanDelete();
		
		if (waf != null && canDelete) {
			wafService.deleteById(wafId);
			model.addAttribute("waf", new Waf());
			return RestResponse.success("Successfully deleted.");
		} else {
			
			// For now we can't do this.
			String error = "The user has attempted to delete a WAF with application mappings.";
			log.warn(error);
			return RestResponse.failure(error);
		}
	}

	@RequestMapping(value = "/{wafId}/rules/download/app/{appId}", method = RequestMethod.GET)
	public ModelAndView download(@PathVariable("wafId") int wafId,
                                 @PathVariable("appId") int wafAppId,
			HttpServletResponse response, HttpServletRequest request) throws IOException {
		Waf waf = wafService.loadWaf(wafId);
		if (waf == null)
			return null;

        Application application = null;
        if (wafAppId != -1) {
            application = applicationService.loadApplication(wafAppId);
            if (application == null
                    || application.getWaf() == null
                    || application.getWaf().getId() != wafId) {
                return null;
            }
        }
        List<WafRule> ruleList;
		if (waf.getWafRules() == null)
            ruleList = wafService.generateWafRules(waf, new WafRuleDirective(), application);
		else {
            ruleList = wafService.getAppRules(waf, application);
        }
		String pageString = wafService.getRulesText(waf, ruleList);
		
		if (pageString == null) {
			return detail(wafId, request);
		}
        String appName = null;
        if (application == null)
            appName = "_AllApplications";
        else
            appName = "_" + application.getOrganization().getName() + "_" + application.getName();
		
		response.setContentType("application/octet-stream");
		response.setHeader("Content-Disposition", "attachment; filename=\"wafrules_" + wafId
				+ appName + ".txt\"");
		
		ServletOutputStream out = response.getOutputStream();
		InputStream in = new ByteArrayInputStream(pageString.getBytes("UTF-8"));
		byte[] outputByte = new byte[65535];
		
		// copy binary content to output stream
		int numToTransfer = in.read(outputByte, 0, 65535);
		while (numToTransfer != -1) {
			out.write(outputByte, 0, numToTransfer);
			numToTransfer = in.read(outputByte, 0, 65535);
		}
		in.close();
		out.flush();
		out.close();
		return null;
	}
}
