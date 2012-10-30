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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
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
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.service.channel.ChannelImporter;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scans/upload")
@PreAuthorize("hasRole('ROLE_CAN_UPLOAD_SCANS')")
public class UploadScanController {

	private ScanService scanService;
	private ApplicationService applicationService;
	private ApplicationChannelService applicationChannelService;
	private OrganizationService organizationService;
	
	private final SanitizedLogger log = new SanitizedLogger(UploadScanController.class);

	@Autowired
	public UploadScanController(ScanService scanService,
			OrganizationService organizationService,
			ApplicationService applicationService,
			ApplicationChannelService applicationChannelService) {
		this.scanService = scanService;
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.applicationChannelService = applicationChannelService;
	}
	
	public UploadScanController(){}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView uploadIndex(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {

		if (!organizationService.isAuthorized(orgId)){
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
		
		if (application.getUploadableChannels() == null || application.getUploadableChannels().size() == 0) {
			log.info("The Application didn't have any channels, redirecting to the Add Channel page.");
			return new ModelAndView("redirect:/organizations/" + orgId + 
									"/applications/" + appId + "/addChannel");
		}
		
		ModelAndView mav = new ModelAndView("scans/upload");
		mav.addObject(application);
		mav.addObject("message",message);
		mav.addObject("type",type);
		return mav;
	}
	
	@RequestMapping(method = RequestMethod.POST)
	public ModelAndView uploadSubmit(@PathVariable("appId") int appId, 
			@PathVariable("orgId") int orgId, HttpServletRequest request,
			@RequestParam("channelId") Integer channelId, @RequestParam("file") MultipartFile file) {
		
		if (!organizationService.isAuthorized(orgId)){
			return new ModelAndView("403");
		}
		
		ScanCheckResultBean returnValue = null;
		
		String fileName = scanService.saveFile(channelId, file);
		
		if (fileName == null || fileName.equals("")) {
			log.warn("Saving the file to disk did not return a file name. Returning to scan upload page.");
			return index(appId, orgId, "Unable to save the file to disk.", null);
		}
		
		try {
			returnValue = scanService.checkFile(channelId, fileName);
		} catch (OutOfMemoryError e) {
			log.error("OutOfMemoryError thrown while checking file. Logging and re-throwing.", e);
			request.getSession().setAttribute("scanErrorMessage", 
					"OutOfMemoryError encountered while checking file.");
			throw e;
		}
		
		Application app = applicationService.loadApplication(appId);
		
		if (app == null || !app.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application",appId));
			throw new ResourceNotFoundException();
		}

		if (returnValue != null && returnValue.getScanCheckResult() != null &&
				ChannelImporter.SUCCESSFUL_SCAN.equals(returnValue.getScanCheckResult())) {
			scanService.addFileToQueue(channelId, fileName, returnValue.getTestDate());
		} else if (returnValue != null && returnValue.getScanCheckResult() != null &&
				ChannelImporter.EMPTY_SCAN_ERROR.equals(returnValue.getScanCheckResult())) {
			Integer emptyScanId = scanService.saveEmptyScanAndGetId(channelId, fileName);
			ModelAndView confirmPage = new ModelAndView("scans/confirm");
			confirmPage.addObject("scanId", emptyScanId);
			return confirmPage;
		} else {
			if (app.getId() != null && app.getOrganization() != null 
					&& app.getOrganization().getId() != null) {
				ChannelType channelType = null;
				
				if (returnValue.getScanCheckResult() != null && 
						(returnValue.getScanCheckResult().equals(ChannelImporter.BADLY_FORMED_XML) ||
						returnValue.getScanCheckResult().equals(ChannelImporter.WRONG_FORMAT_ERROR) ||
						returnValue.getScanCheckResult().equals(ChannelImporter.OTHER_ERROR))) {
					ApplicationChannel appChannel = applicationChannelService.loadApplicationChannel(channelId);
					channelType = appChannel.getChannelType();
				}
 				
				return index(app.getOrganization().getId(), app.getId(), 
								returnValue.getScanCheckResult(), channelType);
			} else {
				log.warn("The request included an invalidly configured " +
						 "Application, throwing ResourceNotFoundException.");
				throw new ResourceNotFoundException();
			}
		}

		if (app.getOrganization() != null) {
			request.getSession().setAttribute("scanSuccessMessage", 
					"The scan was successfully added to the queue for processing.");
			return new ModelAndView("redirect:/organizations/" + app.getOrganization().getId() + 
					"/applications/" + app.getId());
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
		
		if (!organizationService.isAuthorized(orgId)){
			return new ModelAndView("403");
		}
		
		scanService.addEmptyScanToQueue(emptyScanId);
		
		Application app = applicationService.loadApplication(appId);
		
		if (app == null || !app.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application",appId));
			throw new ResourceNotFoundException();
		}

		if (app.getOrganization() != null && app.getOrganization().getId() != null) {
			request.getSession().setAttribute("scanSuccessMessage", 
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
		
		if (!organizationService.isAuthorized(orgId)){
			return "403";
		}
		
		scanService.deleteEmptyScan(emptyScanId);		
		return "redirect:/organizations/" + orgId + "/applications/" + appId + "/scans/upload";
	}
}
