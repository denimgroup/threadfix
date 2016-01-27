////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scans")
@SessionAttributes("application")
public class ScanController {

	private final SanitizedLogger log = new SanitizedLogger(ScanController.class);

	@Autowired
	private ScanService scanService;
	@Autowired
	private ScanDeleteService scanDeleteService;
	@Autowired
	private FindingService findingService;
	@Autowired
	private GenericVulnerabilityService genericVulnerabilityService;
	@Autowired
	private DefaultConfigService defaultConfigService;
	@Autowired
	private VulnerabilityFilterService vulnerabilityFilterService;
	@Autowired
	private ApplicationService applicationService;

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
		if ((scan == null) || (scan.getApplication() == null) || (!scan.getApplication().isActive())) {
			log.warn(ResourceNotFoundException.getLogMessage("Scan", scanId));
			throw new ResourceNotFoundException();
		}

		long numFindings = scanService.getFindingCount(scanId);

		Application application = applicationService.loadApplication(appId);
		ModelAndView mav = new ModelAndView("scans/detail");
		mav.addObject("totalFindings", numFindings);
		mav.addObject(scan);
		mav.addObject("vulnData", scan.getReportList());
		mav.addObject(application);
		PermissionUtils.addPermissions(mav, orgId, appId, Permission.CAN_UPLOAD_SCANS);

		return mav;
	}

	@RequestMapping(value = "/{scanId}/delete", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> deleteScan(@PathVariable("orgId") Integer orgId,
														 @PathVariable("appId") Integer appId,
														 @PathVariable("scanId") Integer scanId,
                                                         HttpServletRequest request) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
			return RestResponse.failure("You do not have permission to delete scans.");
		}

		if (scanId != null) {
			Scan scan = scanService.loadScan(scanId);

			if ((scan != null) && (scan.getApplication() != null) && (scan.getApplication().isActive())) {
				Application application = scan.getApplication();
				List<Scan> scans = scan.getApplication().getScans();
				scanDeleteService.deleteScan(scan);

				scans.remove(scan);
				scan.getApplicationChannel().getScanList().remove(scan);
                request.getSession().setAttribute("application", application);

				vulnerabilityFilterService.updateStatistics(application.getOrganization().getId(), application.getId());
			}
		}

		return RestResponse.success("Successfully deleted scan.");
	}

	@RequestMapping(value = "/{scanId}/download/{scanFileName}", method = RequestMethod.GET)
	public @ResponseBody RestResponse<String> downloadScan(@PathVariable("orgId") Integer orgId,
														   @PathVariable("appId") Integer appId,
														   @PathVariable("scanId") Integer scanId,
														   @PathVariable("scanFileName") String scanFileName,
														   HttpServletResponse response) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
			return RestResponse.failure("You do not have permission to download scans.");
		}

		DefaultConfiguration defaultConfiguration = defaultConfigService.loadCurrentConfiguration();

		if (!defaultConfiguration.fileUploadLocationExists()) {
			return RestResponse.failure("There is no place to download scans from.");
		}

		if (scanId != null) {
			Scan scan = scanService.loadScan(scanId);
			if ((scan != null) && (scan.getApplication() != null) && (scan.getApplication().isActive())) {

				if (scan.getFileName()== null || scan.getFileName().isEmpty()){
					return RestResponse.failure("There is no scan file uploaded associated with this Scan.");
				}

				List<String> fullFilePaths = defaultConfiguration.getFullFilePaths(scan);
				String failureMsg;

				for (int i = 0; i< fullFilePaths.size(); i++ ) {

					String fullFileName = fullFilePaths.get(i);

					if (fullFileName.endsWith(scanFileName)) {
						String originalFileName = (scan.getOriginalFileNames().size() > i ? scan.getOriginalFileNames().get(i) : scanFileName);
						failureMsg = scanService.downloadScan(scan, fullFileName, response, originalFileName);
						if (failureMsg != null) {
							return RestResponse.failure(failureMsg);
						}
						return null;
					}
				}

				return RestResponse.failure("Unable to find file with name " + scanFileName);

			} else {
				return RestResponse.failure("There is no valid scan file.");
			}
		}

		// don't return anything on null
		return null;
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(value = "/{scanId}/table", method = RequestMethod.POST)
	public @ResponseBody Object scanTable(
			@ModelAttribute TableSortBean bean,
			@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId,
			@PathVariable("scanId") Integer scanId) throws IOException {

		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS,orgId,appId)) {
			return "403";
		}

		Scan scan = scanService.loadScan(scanId);
		if ((scan == null) || (scan.getApplication() == null) || (!scan.getApplication().isActive())) {
			log.warn(ResourceNotFoundException.getLogMessage("Scan", scanId));
			throw new ResourceNotFoundException();
		}

		long numFindings = scanService.getFindingCount(scanId);
		long numPages = numFindings / Finding.NUMBER_ITEM_PER_PAGE;

		if (numFindings % Finding.NUMBER_ITEM_PER_PAGE == 0) {
			numPages -= 1;
		}

		if (bean.getPage() > numPages) {
			bean.setPage((int) (numPages + 1));
		}

		if (bean.getPage() < 1) {
			bean.setPage(1);
		}

		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("numPages", numPages);
		responseMap.put("page", bean.getPage());
		responseMap.put("numFindings", numFindings);
		responseMap.put("findingList", findingService.getFindingTable(scanId, bean));
		responseMap.put("scan", scan);

		return RestResponse.success(responseMap);
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(value = "/{scanId}/unmappedTable", method = RequestMethod.POST)
	public @ResponseBody Object unmappedScanTable(Model model,
												  @ModelAttribute TableSortBean bean,
												  @PathVariable("scanId") Integer scanId,
												  @PathVariable("appId") Integer appId,
												  @PathVariable("orgId") Integer orgId) throws IOException {

		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS,orgId,appId)) {
			return "403";
		}

		Scan scan = scanService.loadScan(scanId);
		if ((scan == null) || (scan.getApplication() == null) || (!scan.getApplication().isActive())) {
			log.warn(ResourceNotFoundException.getLogMessage("Scan", scanId));
			throw new ResourceNotFoundException();
		}

		long numFindings = scanService.getUnmappedFindingCount(scanId);

		if (bean.getPage() < 1) {
			bean.setPage(1);
		}

		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("page", bean.getPage());
		responseMap.put("numFindings", numFindings);
		responseMap.put("findingList", findingService.getUnmappedFindingTable(scanId, bean));
		responseMap.put("scan", scan);

		return RestResponse.success(responseMap);
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(value = "/{scanId}/objects")
	public @ResponseBody Object getBaseObjects(@PathVariable("scanId") Integer scanId) throws IOException {
		Map<String, Object> map = new HashMap<>();

		Scan scan = scanService.loadScan(scanId);
		if ((scan == null) || (scan.getApplication() == null) || (!scan.getApplication().isActive())) {
			log.warn(ResourceNotFoundException.getLogMessage("Scan", scanId));
			throw new ResourceNotFoundException();
		}

		// basic information
		// check if scan file can be downloaded
		DefaultConfiguration defaultConfiguration = defaultConfigService.loadCurrentConfiguration();
		scan.setDownloadable(defaultConfiguration.fileUploadLocationExists()
				&& DiskUtils.isFileExists(defaultConfiguration.getFullFilePath(scan)));

		map.put("scan", scan);

		return success(map);
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(value = "/{scanId}/cwe", method = RequestMethod.GET)
	public @ResponseBody Object getGenericVulnerabilities() throws IOException {
		return RestResponse.success(genericVulnerabilityService.loadAll());
	}
}
