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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.plugin.scanner.service.ScanTypeCalculationService;
import com.denimgroup.threadfix.plugin.scanner.service.channel.ScanImportStatus;
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.ScanService;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scans/upload")
public class UploadScanController {
	
	public static final String SCANNER_TYPE_ERROR = "ThreadFix was unable to find a suitable " +
			"scanner type for the file. Please choose one from the list.";

	private ScanService scanService;
	private ScanTypeCalculationService scanTypeCalculationService;
	private ChannelTypeService channelTypeService;
	private ApplicationService applicationService;
	private ApplicationChannelService applicationChannelService;
	private PermissionService permissionService;
	
	private final SanitizedLogger log = new SanitizedLogger(UploadScanController.class);

	@Autowired
	public UploadScanController(ScanService scanService,
			ChannelTypeService channelTypeService,
			ScanTypeCalculationService scanTypeCalculationService,
			PermissionService permissionService,
			ApplicationService applicationService,
			ApplicationChannelService applicationChannelService) {
		this.scanService = scanService;
		this.scanTypeCalculationService = scanTypeCalculationService;
		this.permissionService = permissionService;
		this.applicationService = applicationService;
		this.channelTypeService = channelTypeService;
		this.applicationChannelService = applicationChannelService;
	}
	
	public UploadScanController(){}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView uploadIndex(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {

		if (!permissionService.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)){
			return new ModelAndView("403");
		}
		
		return index(orgId, appId, null, null);
	}
	
	private ModelAndView index(int orgId, int appId, String message, ChannelType type) {

		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}

		ModelAndView mav = new ModelAndView("ajaxFailureHarness");
		mav.addObject(application);
		mav.addObject("message",message);
		if (message != null && message.equals(SCANNER_TYPE_ERROR)) {
			mav.addObject("showTypeSelect", true);
		}
		mav.addObject("channelTypes",channelTypeService.getChannelTypeOptions(null));
		mav.addObject("type",type);
		mav.addObject("contentPage","applications/forms/uploadScanForm.jsp");
		return mav;
	}
	
	// TODO move some of this to the service layer
	@RequestMapping(method = RequestMethod.POST)
	public ModelAndView uploadSubmit(@PathVariable("appId") int appId, 
			@PathVariable("orgId") int orgId, HttpServletRequest request,
			@RequestParam("file") MultipartFile file) {
		
		if (!permissionService.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)){
			return new ModelAndView("403");
		}
		
		Integer myChannelId = scanTypeCalculationService.calculateScanType(appId, file, request.getParameter("channelId"));
		
		if (myChannelId == null) {
			log.warn("ThreadFix was unable to figure out what scanner type to use.");
			return index(orgId, appId, SCANNER_TYPE_ERROR, null);
		}
		
		ScanCheckResultBean returnValue;
		
		String fileName = scanTypeCalculationService.saveFile(myChannelId, file);
		
		if (fileName == null || fileName.equals("")) {
			log.warn("Saving the file to disk did not return a file name. Returning to scan upload page.");
			return index(orgId, appId, "Unable to save the file to disk.", null);
		}
		
		try {
			returnValue = scanService.checkFile(myChannelId, fileName);
		} catch (OutOfMemoryError e) {
			log.error("OutOfMemoryError thrown while checking file. Logging and re-throwing.", e);
			ControllerUtils.addErrorMessage(request, "OutOfMemoryError encountered while checking file.");
			throw e;
		}
		
		Application app = applicationService.loadApplication(appId);
		
		if (app == null || !app.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application",appId));
			throw new ResourceNotFoundException();
		}

		if (returnValue != null && returnValue.getScanCheckResult() != null &&
				ScanImportStatus.SUCCESSFUL_SCAN.equals(returnValue.getScanCheckResult())) {
			if (app.getScans() == null) {
				ControllerUtils.addItem(request, "numScansBeforeUpload", 0);
			} else {
				ControllerUtils.addItem(request, "numScansBeforeUpload", app.getScans().size());
			}
			scanService.addFileToQueue(myChannelId, fileName, returnValue.getTestDate());
		} else if (returnValue != null && returnValue.getScanCheckResult() != null &&
				ScanImportStatus.EMPTY_SCAN_ERROR.equals(returnValue.getScanCheckResult())) {
			Integer emptyScanId = scanService.saveEmptyScanAndGetId(myChannelId, fileName);
			ModelAndView confirmPage = new ModelAndView("scans/confirm");
			confirmPage.addObject("scanId", emptyScanId);
			return confirmPage;
		} else {
			if (app.getId() != null && app.getOrganization() != null 
					&& app.getOrganization().getId() != null) {
				ChannelType channelType = null;
				
				if (returnValue != null && returnValue.getScanCheckResult() != null &&
						(returnValue.getScanCheckResult().equals(ScanImportStatus.BADLY_FORMED_XML) ||
						returnValue.getScanCheckResult().equals(ScanImportStatus.WRONG_FORMAT_ERROR) ||
						returnValue.getScanCheckResult().equals(ScanImportStatus.OTHER_ERROR))) {
					ApplicationChannel appChannel = applicationChannelService.loadApplicationChannel(myChannelId);
					channelType = appChannel.getChannelType();
				}
 				
				return index(app.getOrganization().getId(), app.getId(), 
								returnValue.getScanCheckResult().toString(), channelType);
			} else {
				log.warn("The request included an invalidly configured " +
						 "Application, throwing ResourceNotFoundException.");
				throw new ResourceNotFoundException();
			}
		}

		if (app.getOrganization() != null) {
			ControllerUtils.addSuccessMessage(request, 
					"The scan was successfully submitted for processing. This page will refresh when it finishes.");
			ControllerUtils.addItem(request, "checkForRefresh", 1);
			ModelAndView mav = new ModelAndView("ajaxRedirectHarness");
			mav.addObject("contentPage","/organizations/" + orgId + "/applications/" + appId);
			return mav;
		} else {
			log.warn("Redirecting to the jobs page because it was impossible to redirect to the Application.");
			return new ModelAndView("redirect:/jobs/open");
		}
	}
	
	@RequestMapping(value = "/{emptyScanId}/confirm", method = RequestMethod.GET)
	public ModelAndView confirm(@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId, 
			@PathVariable("emptyScanId") Integer emptyScanId,
			HttpServletRequest request) {
		
		if (!permissionService.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)){
			return new ModelAndView("403");
		}
		
		scanService.addEmptyScanToQueue(emptyScanId);
		
		Application app = applicationService.loadApplication(appId);
		
		if (app == null || !app.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application",appId));
			throw new ResourceNotFoundException();
		}

		if (app.getOrganization() != null && app.getOrganization().getId() != null) {
			ControllerUtils.addSuccessMessage(request, 
					"The empty scan was successfully added to the queue for processing.");
			return new ModelAndView("redirect:/organizations/" + app.getOrganization().getId() + 
					"/applications/" + app.getId());
		} else {
			return new ModelAndView("redirect:/jobs/open");
		}
	}
	
	@RequestMapping(value = "/{emptyScanId}/cancel", method = RequestMethod.GET)
	public String cancel(@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId, 
			@PathVariable("emptyScanId") Integer emptyScanId) {
		
		if (!permissionService.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)){
			return "403";
		}
		
		scanService.deleteEmptyScan(emptyScanId);		
		return "redirect:/organizations/" + orgId + "/applications/" + appId + "/scans/upload";
	}
}
