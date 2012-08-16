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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.service.WafService;

@Controller
@RequestMapping("/wafs")
public class WafsController {

	private WafService wafService = null;
	
	private final Log log = LogFactory.getLog(WafsController.class);

	@Autowired
	public WafsController(WafService wafService) {
		this.wafService = wafService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(ModelMap model) {
		model.addAttribute(wafService.loadAll());
		return "wafs/index";
	}

	@RequestMapping("/{wafId}")
	public ModelAndView detail(@PathVariable("wafId") int wafId) {
		ModelAndView mav = new ModelAndView("wafs/detail");
		Waf waf = wafService.loadWaf(wafId);
		
		if (waf == null) {
			log.warn(ResourceNotFoundException.getLogMessage("WAF", wafId));
			throw new ResourceNotFoundException();
		}
		
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
		
		boolean hasApps = false;
		if (waf.getApplications() != null) {
			for (Application application : waf.getApplications()) {
				if (application.isActive()) {
					hasApps = true;
					break;
				}
			}
		}
		
		String rulesText = wafService.getAllRuleText(waf);
		
		mav.addObject(waf);
		mav.addObject("rulesText", rulesText);
		mav.addObject("hasApps", hasApps);
		mav.addObject("lastDirective", lastDirective);
		mav.addObject("directives", directives);
		
		return mav;
	}

	@RequestMapping("/{wafId}/delete")
	public String deleteWaf(@PathVariable("wafId") int wafId, SessionStatus status) {
		Waf waf = wafService.loadWaf(wafId);
		if (waf != null && (waf.getApplications() == null || waf.getApplications().isEmpty())) {
			wafService.deleteById(wafId);
			status.setComplete();
			return "redirect:/wafs";
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("WAF", wafId));
			throw new ResourceNotFoundException();
		}
	}

	@RequestMapping(value = "/{wafId}", method = RequestMethod.POST)
	public ModelAndView download(@PathVariable("wafId") int wafId, HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		Waf waf = wafService.loadWaf(wafId);
		if (waf == null)
			return null;
		if (waf.getWafRules() == null)
			wafService.generateWafRules(waf, new WafRuleDirective());
		
		String pageString = wafService.getAllRuleText(waf);
		
		if (pageString == null) {
			return detail(wafId);
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
