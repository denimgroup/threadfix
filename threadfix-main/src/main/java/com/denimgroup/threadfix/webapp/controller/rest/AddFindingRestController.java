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

package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.ManualFindingService;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@RestController
@RequestMapping("/rest/applications/{appId}/addFinding")
public class AddFindingRestController extends TFRestController {
	
	public static final String CREATION_FAILED = "New Finding creation failed.";
	public static final String INVALID_DESCRIPTION = "The longDescription parameter " +
			"needs to be set to a String between 1 and " + 
			Finding.LONG_DESCRIPTION_LENGTH + " characters long.";
	
	public static final String INVALID_VULN_NAME = "The vulnType parameter needs to be " +
			"set to a valid CWE vulnerability name.";

	public static final String INVALID_SEVERITY = "The severity parameter needs to be one of [1,2,3,4,5].";
	public static final String PASSED_CHECK = "The request passed the check for Finding parameters.";

    @Autowired
	private ManualFindingService manualFindingService;
    @Autowired
	private FindingService findingService;
	
	private final static String NEW = "newFinding";

	/**
	 * Create a new manual finding.
	 * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#addDynamicFinding()
	 */
	@RequestMapping(headers="Accept=application/json", value="", method=RequestMethod.POST)
	@JsonView(AllViews.RestView2_1.class)
	public Object createFinding(HttpServletRequest request,
			@PathVariable("appId") int appId) {
		log.info("Received REST request for a new Finding.");

		String result = checkKey(request, NEW);
		if (!result.equals(API_KEY_SUCCESS)) {
			return failure(result);
		}
		// By not using @RequestParam notations, we can catch the error in the code
		// and provide better error messages.
		 
		String checkResult = findingService.checkRequestForFindingParameters(request);
		if (!checkResult.equals(PASSED_CHECK)) {
            return failure(checkResult);
        }
		
		Finding finding = findingService.parseFindingFromRequest(request);
		boolean mergeResult = manualFindingService.processManualFinding(finding, appId);
		
		if (mergeResult) {
			return success(finding);
		} else {
			return failure("There was an error merging the new Finding.");
		}
	}
}
