package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.plugin.scanner.service.ScanTypeCalculationService;
import com.denimgroup.threadfix.plugin.scanner.service.channel.ScanImportStatus;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DocumentService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.ScanParametersService;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.webapp.viewmodels.ScanParametersBean;

@Controller
@RequestMapping("/rest/applications")
public class ApplicationRestController extends RestController {
	
	public static final String CREATION_FAILED = "New Application creation failed.";
	public static final String LOOKUP_FAILED = "Application lookup failed.";
	public static final String ADD_CHANNEL_FAILED = "Adding an Application Channel failed.";
	public static final String SET_WAF_FAILED = "Call to setWaf failed.";
	public static final String CHANNEL_LOOKUP_FAILED = "Application Channel lookup failed.";
	
	private ApplicationService applicationService;
	private DocumentService documentService;
	private ScanService scanService;
	private ScanParametersService scanParametersService;
	private ScanTypeCalculationService scanTypeCalculationService;
	private ScanMergeService scanMergeService;
	private WafService wafService;
	private OrganizationService organizationService;
	
	private final static String DETAIL = "applicationDetail", 
		SET_PARAMS = "setParameters",
		LOOKUP = "applicationLookup",
		NEW = "newApplication",
		SET_WAF = "setWaf",
		UPLOAD = "uploadScan",
		ATTACH_FILE = "attachFile",
		SET_URL = "setUrl";

	// TODO finalize which methods need to be restricted
	static {
		restrictedMethods.add(NEW);
		restrictedMethods.add(SET_WAF);
	}
	
	@Autowired
	public ApplicationRestController(APIKeyService apiKeyService, 
			ApplicationService applicationService,
			DocumentService documentService,
			OrganizationService organizationService,
			ScanService scanService, 
			ScanMergeService scanMergeService,
			ScanTypeCalculationService scanTypeCalculationService, 
			WafService wafService,
			ScanParametersService scanParametersService) {
		super(apiKeyService);
		this.organizationService = organizationService;
		this.apiKeyService = apiKeyService;
		this.applicationService = applicationService;
		this.documentService = documentService;
		this.scanTypeCalculationService = scanTypeCalculationService;
		this.scanService = scanService;
		this.scanMergeService = scanMergeService;
		this.wafService = wafService;
		this.scanParametersService = scanParametersService;
	}
	
	/**
	 * Return details about a specific application.
	 * @param request
	 * @param appId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/{appId}", method=RequestMethod.GET)
	public @ResponseBody Object applicationDetail(HttpServletRequest request,
			@PathVariable("appId") int appId) {
		log.info("Received REST request for Applications with id = " + appId + ".");

		String result = checkKey(request, DETAIL);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(LOOKUP_FAILED);
			return LOOKUP_FAILED;
		}
		return application;
	}
	
	/**
	 * Set scan parameters
	 * @param request
	 * @param appId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/{appId}/attachFile", method=RequestMethod.POST)
	public @ResponseBody Object attachFile(HttpServletRequest request,
			@PathVariable("appId") int appId,
			@RequestParam("file") MultipartFile file,
			@RequestParam("filename") String filename) {
		log.info("Received REST request to attach a file to application with id = " + appId + ".");
		
		String result = checkKey(request, ATTACH_FILE);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		if(filename != null) {
			documentService.saveFileToApp(appId, file, filename);
		} else {
			documentService.saveFileToApp(appId, file);
		}
		
		//	TODO - Make this response better.
		return "OK";
	}
	
	/**
	 * Set scan parameters
	 * @param request
	 * @param appId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/{appId}/setParameters", method=RequestMethod.POST)
	public @ResponseBody Object setParameters(HttpServletRequest request,
			@PathVariable("appId") int appId) {
		log.info("Received REST request to set parameters for application with id = " + appId + ".");
		
		String result = checkKey(request, SET_PARAMS);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(LOOKUP_FAILED);
			return LOOKUP_FAILED;
		}
		
		ScanParametersBean bean = new ScanParametersBean();
		
		if (request.getParameter("sourceCodeAccessLevel") != null) {
			bean.setSourceCodeAccessLevel(request.getParameter("sourceCodeAccessLevel"));
		}
		
		if (request.getParameter("frameworkType") != null) {
			bean.setApplicationType(request.getParameter("frameworkType"));
		}
		
		if (request.getParameter("repositoryUrl") != null) {
			bean.setSourceCodeUrl(request.getParameter("repositoryUrl"));
		}
		
		scanParametersService.saveConfiguration(application, bean);
		
		return application;
	}
	
	/**
	 * Return details about a specific application.
	 * @param request
	 * @param appName
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/{teamId}/lookup", method=RequestMethod.GET)
	public @ResponseBody Object applicationLookup(HttpServletRequest request,
			@PathVariable("teamId") String teamName) {		
		String appName = request.getParameter("name");
		String result = checkKey(request, LOOKUP);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}		
		if (appName == null) {
			return LOOKUP_FAILED;
		}		
		log.info("Received REST request for Applications in team = " + teamName + ".");		
		Organization org = organizationService.loadOrganization(teamName);				
		if (org == null) {
			log.warn(LOOKUP_FAILED);
			return LOOKUP_FAILED;
		}
		
		int teamId = org.getId();
		Application application = applicationService.loadApplication(appName, teamId);	
		
		if (application == null) {
			log.warn(LOOKUP_FAILED);
			return LOOKUP_FAILED;
		}
		return application;
	}
	
	/**
	 * Allows the user to upload a scan to an existing application channel.
	 * @param appId
	 * @param request
	 * @param applicationId
	 * @param file
	 * @return Status response. We may change this to make it more useful.
	 */
	@RequestMapping(headers="Accept=application/json", value="/{appId}/upload", method=RequestMethod.POST)
	public @ResponseBody Object uploadScan(@PathVariable("appId") int appId, 
			HttpServletRequest request, @RequestParam("file") MultipartFile file) {
		log.info("Received REST request to upload a scan to application " + appId + ".");

		String result = checkKey(request, UPLOAD);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Integer myChannelId = scanTypeCalculationService.calculateScanType(appId, file, request.getParameter("channelId"));
		
		String fileName = scanTypeCalculationService.saveFile(myChannelId, file);
		
		ScanCheckResultBean returnValue = scanService.checkFile(myChannelId, fileName);
		
		if (ScanImportStatus.SUCCESSFUL_SCAN == returnValue.getScanCheckResult()) {
			Scan scan = scanMergeService.saveRemoteScanAndRun(myChannelId, fileName);
			return scan;
		} else if (ScanImportStatus.EMPTY_SCAN_ERROR == returnValue.getScanCheckResult()) {
			return "You attempted to upload an empty scan.";
		} else {
			return "The scan upload attempt returned this message: " + returnValue.getScanCheckResult();
		}
	}
	
	/**
	 * Overwrites the WAF for the application.
	 * @param request
	 * @param appId
	 * @param wafId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/{appId}/setWaf", method=RequestMethod.POST)
	public @ResponseBody Object setWaf(HttpServletRequest request,
			@PathVariable("appId") int appId) {
		
		String idString = request.getParameter("wafId");
		
		Integer wafId = null;
		
		if (idString != null) {
			try {
				wafId = Integer.valueOf(idString);
			} catch (NumberFormatException e) {
				log.warn("Non-integer parameter was submitted to setWaf.");
			}
			if (wafId != null) {
				log.info("Received REST request to add WAF " + wafId + " to Application " + appId + ".");
			}
		}
		
		if (wafId == null) {
			log.warn("Received incomplete REST request to add a WAF");
			return SET_WAF_FAILED;
		}

		String result = checkKey(request, SET_WAF);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Application application = applicationService.loadApplication(appId);
		Waf waf = wafService.loadWaf(wafId);
		
		if (application == null) {
			log.warn("Invalid Application ID.");
			return SET_WAF_FAILED;
		} else if (waf == null) {
			log.warn("Invalid WAF ID");
			return SET_WAF_FAILED;
		} else {
			
			// Delete WAF rules if the WAF has changed
			Integer oldWafId = null;
			
			if (application.getWaf() != null && application.getWaf().getId() != null) {
				oldWafId = application.getWaf().getId();
			}
			
			application.setWaf(waf);
			applicationService.updateWafRules(application, oldWafId);
			applicationService.storeApplication(application);
			return application;
		}
	}
	
	
	/**
	 * Set the URL for the application.
	 * @param request
	 * @param appId
	 * @param wafId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/{appId}/addUrl", method=RequestMethod.POST)
	public @ResponseBody Object setUrl(HttpServletRequest request,
			@PathVariable("appId") int appId) {
		
		String url = request.getParameter("url");

		String result = checkKey(request, SET_URL);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn("Invalid Application ID.");
			return SET_WAF_FAILED;
		} else {
			application.setUrl(url);
			applicationService.storeApplication(application);
			return application;
		}
	}
}
