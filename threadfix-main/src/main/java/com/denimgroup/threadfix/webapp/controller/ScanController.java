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

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.ScanDeleteService;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scans")
public class ScanController {
	
	private final SanitizedLogger log = new SanitizedLogger(ScanController.class);

    @Autowired
	private ScanService scanService;
    @Autowired
	private ScanDeleteService scanDeleteService;
    @Autowired
	private FindingService findingService;

	@InitBinder
	protected void initBinder(WebDataBinder binder) {
		binder.setValidator(new BeanValidator());
	}

	@RequestMapping(value = "/{scanId}", method = RequestMethod.GET)
	public ModelAndView detailScan(@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId,
			@PathVariable("scanId") Integer scanId) {
		
		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS,orgId,appId)){
			return new ModelAndView("403");
		}
		
		Scan scan = null;
		if (scanId != null) {
			scan = scanService.loadScan(scanId);
			scanService.loadStatistics(scan);
		}
		if (scan == null) {
			if (orgId != null && appId != null) {
				return new ModelAndView("redirect:/organizations/" + orgId + "/applications/" + appId + "/scans");
			} else if (orgId != null) {
				return new ModelAndView("redirect:/organizations/" + orgId);
			} else {
				return new ModelAndView("redirect:/");
			}
		}
		
		long numFindings = scanService.getFindingCount(scanId);
		
		ModelAndView mav = new ModelAndView("scans/detail");
		mav.addObject("totalFindings", numFindings);
		mav.addObject(scan);
		mav.addObject("vulnData", scan.getReportList());
		return mav;
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_UPLOAD_SCANS')")
	@RequestMapping(value = "/{scanId}/delete", method = RequestMethod.POST)
	public ModelAndView deleteScan(@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId,
			@PathVariable("scanId") Integer scanId,
			HttpServletRequest request) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
			return new ModelAndView("403");
		}
		
		if (scanId != null) {
			Scan scan = scanService.loadScan(scanId);
			if (scan != null) {
				scanDeleteService.deleteScan(scan);
			}
		}
		
		ControllerUtils.addSuccessMessage(request, "The scan was successfully deleted.");
        ControllerUtils.setActiveTab(request, ControllerUtils.SCAN_TAB);
		return new ModelAndView("redirect:/organizations/" + orgId + "/applications/" + appId);
	}
	
	@RequestMapping(value = "/{scanId}/table", method = RequestMethod.POST)
	public String scanTable(Model model,
			@RequestBody TableSortBean bean,
			@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId,
			@PathVariable("scanId") Integer scanId) {
		
		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS,orgId,appId)) {
			return "403";
		}
		
		Scan scan = scanService.loadScan(scanId);
		if (scan == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Scan", scanId));
			throw new ResourceNotFoundException();
		}

		long numFindings = scanService.getFindingCount(scanId);
		long numPages = numFindings / 100;
		
		if (numFindings % 100 == 0) {
			numPages -= 1;
		}
		
		if (bean.getPage() > numPages) {
			bean.setPage((int) (numPages + 1));
		}
		
		if (bean.getPage() < 1) {
			bean.setPage(1);
		}
				
		model.addAttribute("numPages", numPages);
		model.addAttribute("page", bean.getPage());
		model.addAttribute("numFindings", numFindings);
		model.addAttribute("findingList", findingService.getFindingTable(scanId, bean));
		model.addAttribute(scan);
		return "scans/table";
	}
	
	@RequestMapping(value = "/{scanId}/unmappedTable", method = RequestMethod.POST)
	public String unmappedScanTable(Model model,
			@RequestBody TableSortBean bean,
			@PathVariable("scanId") Integer scanId,
			@PathVariable("appId") Integer appId,
			@PathVariable("orgId") Integer orgId) {
		
		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS,orgId,appId)) {
			return "403";
		}
		
		Scan scan = scanService.loadScan(scanId);
		if (scan == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Scan", scanId));
			throw new ResourceNotFoundException();
		}

		long numFindings = scanService.getUnmappedFindingCount(scanId);
		long numPages = numFindings / 100;
		
		if (numFindings % 100 == 0) {
			numPages -= 1;
		}
		
		if (bean.getPage() >= numPages) {
			bean.setPage((int) (numPages + 1));
		}
		
		if (bean.getPage() < 1) {
			bean.setPage(1);
		}
		
		model.addAttribute("numPages", numPages);
		model.addAttribute("page", bean.getPage());
		model.addAttribute("numFindings", numFindings);
		model.addAttribute("findingList", findingService.getUnmappedFindingTable(scanId, bean));
		model.addAttribute(scan);
		return "scans/unmappedTable";
	}
}
