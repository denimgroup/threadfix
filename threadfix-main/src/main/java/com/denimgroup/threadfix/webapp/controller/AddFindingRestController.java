package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.ManualFindingService;

@Controller
@RequestMapping("/rest/teams/{teamId}/applications/{appId}/addFinding")
public class AddFindingRestController extends RestController {
	
	public static final String CREATION_FAILED = "New Finding creation failed.";
	public static final String INVALID_DESCRIPTION = "The longDescription parameter " +
			"needs to be set to a String between 1 and " + 
			Finding.LONG_DESCRIPTION_LENGTH + " characters long.";
	
	public static final String INVALID_VULN_NAME = "The vulnType parameter needs to be " +
			"set to a valid CWE vulnerability name.";
	public static final String PASSED_CHECK = "The request passed the check for Finding parameters.";

	private ManualFindingService manualFindingService;
	private FindingService findingService;
	
	private final static String NEW = "newFinding";

	@Autowired
	public AddFindingRestController(APIKeyService apiKeyService, 
			ManualFindingService manualFindingService,
			FindingService findingService) {
		this.apiKeyService = apiKeyService;
		this.manualFindingService = manualFindingService;
		this.findingService = findingService;
	}
	
	/**
	 * Create a new manual finding.
	 * 
	 * @param request
	 * @param teamId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="", method=RequestMethod.POST)
	public @ResponseBody Object newApplication(HttpServletRequest request,
			@PathVariable("appId") int appId,
			@PathVariable("teamId") int teamId) {
		log.info("Received REST request for a new Finding.");

		String result = checkKey(request, NEW);
		if (!result.equals(API_KEY_SUCCESS)) {
			return result;
		}
		// By not using @RequestParam notations, we can catch the error in the code
		// and provide better error messages.
		 
		String checkResult = findingService.checkRequestForFindingParameters(request);
		if (checkResult == null || !checkResult.equals(PASSED_CHECK)) {
			return checkResult;
		}
		
		Finding finding = findingService.parseFindingFromRequest(request);
		boolean mergeResult = manualFindingService.processManualFinding(finding, appId);
		
		if (mergeResult) {
			return finding;
		} else {
			return "There was an error merging the new Finding.";
		}
	}
}
