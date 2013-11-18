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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.WafService;

@Controller
@RequestMapping("/wafs")
@SessionAttributes({"newWaf","waf"})
public class WafsController {

	private WafService wafService = null;
	private PermissionService permissionService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(WafsController.class);

	@Autowired
	public WafsController(PermissionService permissionService,
			WafService wafService) {
		this.wafService = wafService;
		this.permissionService = permissionService;
	}
	
	public WafsController(){}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
		List<Waf> wafs = wafService.loadAll();
		model.addAttribute(wafs);
		model.addAttribute("newWaf", new Waf());
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("waf", new Waf());
		model.addAttribute("wafPage", true);
		model.addAttribute("createWafUrl", "wafs/new/ajax");
		model.addAttribute("wafTypeList", wafService.loadAllWafTypes());
		permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_WAFS);
		return "wafs/index";
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
			canSeeRules = permissionService.canSeeRules(waf);
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
			boolean globalAccess = permissionService.isAuthorized(Permission.READ_ACCESS, null,null);
			if (globalAccess) {
				mav.addObject("apps", waf.getApplications());
			} else {
				List<Application> apps = new ArrayList<>();
				
				Set<Integer> authenticatedAppIds = permissionService.getAuthenticatedAppIds();
				Set<Integer> authenticatedTeamIds = permissionService.getAuthenticatedTeamIds();
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
		
		permissionService.addPermissions(mav, null, null, 
				Permission.CAN_MANAGE_WAFS, Permission.CAN_GENERATE_WAF_RULES);
		
		mav.addObject("successMessage", ControllerUtils.getSuccessMessage(request));
		
		return mav;
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_WAFS')")
	@RequestMapping("/{wafId}/delete")
	public String deleteWaf(@PathVariable("wafId") int wafId, 
			SessionStatus status, HttpServletRequest request) {
		Waf waf = wafService.loadWaf(wafId);
		boolean canDelete = waf != null && waf.getCanDelete();
		
		if (waf != null && canDelete) {
			wafService.deleteById(wafId);
			status.setComplete();
			ControllerUtils.addSuccessMessage(request, 
					"The WAF deletion was successful for WAF" + waf.getName() + ".");
			return "redirect:/wafs";
		} else {
			
			// For now we can't do this.
			log.warn("The user has attempted to delete a WAF with application mappings.");
			return "redirect:/wafs/" + wafId;
		}
	}

	@RequestMapping(value = "/{wafId}", method = RequestMethod.POST)
	public ModelAndView download(@PathVariable("wafId") int wafId,
			HttpServletResponse response, HttpServletRequest request) throws IOException {
		Waf waf = wafService.loadWaf(wafId);
		if (waf == null)
			return null;
		if (waf.getWafRules() == null)
			wafService.generateWafRules(waf, new WafRuleDirective());
		
		String pageString = wafService.getAllRuleText(waf);
		
		if (pageString == null) {
			return detail(wafId, request);
		}
		
		response.setContentType("application/octet-stream");
		response.setHeader("Content-Disposition", "attachment; filename=\"wafrules_" + wafId
				+ ".txt\"");
		
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
