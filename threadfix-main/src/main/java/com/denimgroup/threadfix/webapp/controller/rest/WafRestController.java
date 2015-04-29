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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.LogParserService;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@RestController
@RequestMapping("/rest/wafs")
public class WafRestController extends TFRestController {
	
	public static final String CREATION_FAILED = "New WAF creation failed.";
    public static final String NOT_FOUND_WAF = "Invalid WAF type requested.";
	public static final String LOOKUP_FAILED = "WAF Lookup failed.";

    @Autowired
	private WafService wafService;
    @Autowired
	private LogParserService logParserService;
    @Autowired
    private ApplicationService applicationService;
	
	private final static String INDEX = "wafIndex", 
		DETAIL = "wafDetail", 
		LOOKUP = "wafLookup",
		RULES = "getRules",
		NEW = "newWaf",
		LOG = "uploadWafLog";
	
	// TODO decide which methods need to be restricted
	static {
		restrictedMethods.add(NEW);
		restrictedMethods.add(LOG);
		restrictedMethods.add(RULES);
	}

	// TODO figure out if there is an easier way to make Spring respond to both
	@RequestMapping(headers="Accept=application/json", value="", method=RequestMethod.GET)
	public Object wafIndexNoSlash(HttpServletRequest request) {
		return wafIndex(request);
	}

    /**
     * @param request
     * @return
     */
	@JsonView(AllViews.RestViewWaf2_1.class)
	@RequestMapping(headers="Accept=application/json", value="/", method=RequestMethod.GET)
	public Object wafIndex(HttpServletRequest request) {
		log.info("Received REST request for WAFs");

		String result = checkKey(request, INDEX);
		if (!result.equals(API_KEY_SUCCESS)) {
			return failure(result);
		}
		
		List<Waf> wafs = wafService.loadAll();
		
		if (wafs == null || wafs.isEmpty()) {
			log.warn("wafService.loadAll() returned null.");
            return failure("No WAFs found.");
		} else {
            return RestResponse.success(wafs);
        }
	}

    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForWafById(String)
     * @param request
     * @param wafId
     * @return
     */
	@JsonView(AllViews.RestViewWaf2_1.class)
	@RequestMapping(headers="Accept=application/json", value="/{wafId}", method=RequestMethod.GET)
	public Object wafDetail(HttpServletRequest request,
			@PathVariable("wafId") String wafId) {
		int wafIdInt = 0;

		if (wafId.equals("new")) {
			return newWaf(request);
		} else {
			try {
				wafIdInt = Integer.parseInt(wafId);
			} catch (NumberFormatException e) {
				log.warn("Invalid WAF ID");
				return failure("Bad rest request.");
			}
		}

		log.info("Received REST request for WAF with ID = " + wafId + ".");

		String result = checkKey(request, DETAIL);
		if (!result.equals(API_KEY_SUCCESS)) {
			return failure(result);
		}

		Waf waf = wafService.loadWaf(wafIdInt);
		if (waf == null) {
			log.warn("Invalid WAF ID.");
			return failure(LOOKUP_FAILED);
		} else {
            return RestResponse.success(waf);
        }
	}

    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForWafByName(String)
     * @param request
     * @return
     */
	@JsonView(AllViews.RestViewWaf2_1.class)
	@RequestMapping(headers="Accept=application/json", value="/lookup", method=RequestMethod.GET)
	public Object wafLookup(HttpServletRequest request) {
		
		if (request.getParameter("name") == null) {
			log.info("Received REST request for WAF with name = " + request.getParameter("name") + ".");
		} else {
			log.info("Received REST request for WAF with a missing name parameter.");
		}

		String result = checkKey(request, LOOKUP);
		if (!result.equals(API_KEY_SUCCESS)) {
			return failure(result);
		}
		
		if (request.getParameter("name") == null) {
			return failure(LOOKUP_FAILED);
		}
		
		Waf waf = wafService.loadWaf(request.getParameter("name"));
		
		if (waf == null) {
			log.warn("Invalid WAF Name.");
			return failure("Invalid WAF Name.");
		}
        return RestResponse.success(waf);
	}
	
	/**
	 * Returns the current set of rules from the WAF, generating new ones if none are present.
	 */
	@JsonView(AllViews.RestViewWaf2_1.class)
	@RequestMapping(headers="Accept=application/json", value="/{wafId}/rules/app/{appId}", method=RequestMethod.GET)
	public RestResponse<String> getRules(HttpServletRequest request,
			@PathVariable("wafId") int wafId,
            @PathVariable("appId") int wafAppId) {
		log.info("Received REST request for rules from WAF with ID = " + wafId + ".");

		String result = checkKey(request, RULES);
		if (!result.equals(API_KEY_SUCCESS)) {
			return failure(result);
		}
		
		Waf waf = wafService.loadWaf(wafId);
		
		if (waf == null) {
			log.warn("Invalid WAF ID.");
			return failure("Invalid WAF ID.");
		}

        Application application = null;
        if (wafAppId != -1) {
            application = applicationService.loadApplication(wafAppId);
            if (application == null
                    || application.getWaf() == null
                    || application.getWaf().getId() != wafId) {
                log.warn("Invalid Application ID.");
                return failure("Invalid Application ID.");
            }
        }

        List<WafRule> ruleList = wafService.generateWafRules(waf, waf.getLastWafRuleDirective(), application);
        String ruleStr = wafService.getRulesText(waf, ruleList);
        if (ruleStr == null || ruleStr.isEmpty()) {
            return failure("No Rules generated for WAF.");
        } else {
            return success(ruleStr);
        }
	}

	@JsonView(AllViews.RestViewWaf2_1.class)
	@RequestMapping(headers="Accept=application/json", value="/new", method=RequestMethod.POST)
	public Object newWaf(HttpServletRequest request) {
		log.info("Received REST request for a new WAF.");
		
		String result = checkKey(request, NEW);
		if (!result.equals(API_KEY_SUCCESS)) {
			return failure(result);
		}
		
		String name = request.getParameter("name");
		String type = request.getParameter("type");
		
		if (name == null || type == null) {
			log.warn("Request for WAF creation failed because it was missing one or both parameters.");
			return failure(CREATION_FAILED);
		}
		
		WafType wafType = wafService.loadWafType(type);
		
		if (wafType == null) {
			log.warn("Invalid WAF type requested.");
			return failure(NOT_FOUND_WAF);
		}

        Waf existingWaf = wafService.loadWaf(name);

        if (existingWaf != null) {
            return failure("ThreadFix already has a WAF with the name " + name);
        }
		
		if (!name.trim().isEmpty() && name.length() < Waf.NAME_LENGTH) {
			
			Waf waf = new Waf();
			
			waf.setName(name);
			waf.setWafType(wafType);
			
			wafService.storeWaf(waf);
            return RestResponse.success(waf);
		} else {
			return failure(CREATION_FAILED);
		}
	}

	@JsonView(AllViews.RestViewWaf2_1.class)
	@RequestMapping(headers="Accept=application/json", value="/{wafId}/uploadLog", method=RequestMethod.POST)
	public RestResponse uploadWafLog(HttpServletRequest request,
			@PathVariable("wafId") int wafId, @RequestParam("file") MultipartFile file) {
		log.info("Received REST request for a new WAF.");

		String result = checkKey(request, LOG);
		if (!result.equals(API_KEY_SUCCESS)) {
			return failure(result);
		}
		
		Waf waf = wafService.loadWaf(wafId);
		
		String logContents = null;
		
		try {
			byte[] bytes = file.getBytes();
			logContents = new String(bytes);
		} catch (IOException e) {
			log.warn("Malformed file uploaded (or bad code on our part).");
			e.printStackTrace();
		}
		
		if (waf == null || logContents == null || logContents.isEmpty()) {
			log.debug("Invalid input.");
			return failure("Invalid input");
		}
				
		logParserService.setFileAsString(logContents);
		logParserService.setWafId(wafId);
		List<SecurityEvent> events = logParserService.parseInput();
		
		if (events == null || events.size() == 0) {
			log.debug("No Security Events found.");
		} else {
			log.debug("Found " + events.size() + " security events.");
		}
		
		return success(events);
	}
}
