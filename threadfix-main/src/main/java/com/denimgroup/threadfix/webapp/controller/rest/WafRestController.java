package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.LogParserService;
import com.denimgroup.threadfix.service.WafService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

@Controller
@RequestMapping("/rest/wafs")
public class WafRestController extends RestController {
	
	public static final String CREATION_FAILED = "New WAF creation failed.";
    public static final String NOT_FOUND_WAF = "Invalid WAF type requested.";
	public static final String LOOKUP_FAILED = "WAF Lookup failed.";

    @Autowired
	private WafService wafService;
    @Autowired
	private LogParserService logParserService;
	
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
	public @ResponseBody RestResponse<Waf[]> wafIndexNoSlash(HttpServletRequest request) {
		return wafIndex(request);
	}

    /**
     * @param request
     * @return
     */
	@RequestMapping(headers="Accept=application/json", value="/", method=RequestMethod.GET)
	public @ResponseBody RestResponse<Waf[]> wafIndex(HttpServletRequest request) {
		log.info("Received REST request for WAFs");

		String result = checkKey(request, INDEX);
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}
		
		List<Waf> wafs = wafService.loadAll();
		
		if (wafs == null || wafs.isEmpty()) {
			log.warn("wafService.loadAll() returned null.");
            return RestResponse.failure("No WAFs found.");
		} else {
            return RestResponse.success(wafs.toArray(new Waf[wafs.size()]));
        }
	}

    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForWafById(String)
     * @param request
     * @param wafId
     * @return
     */
	@RequestMapping(headers="Accept=application/json", value="/{wafId}", method=RequestMethod.GET)
	public @ResponseBody RestResponse<Waf> wafDetail(HttpServletRequest request,
			@PathVariable("wafId") int wafId) {
		log.info("Received REST request for WAF with ID = " + wafId + ".");

		String result = checkKey(request, DETAIL);
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}
		
		Waf waf = wafService.loadWaf(wafId);
		
		if (waf == null) {
			log.warn("Invalid WAF ID.");
			return RestResponse.failure(LOOKUP_FAILED);
		} else {
            return RestResponse.success(waf);
        }
	}

    /**
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForWafByName(String)
     * @param request
     * @return
     */
	@RequestMapping(headers="Accept=application/json", value="/lookup", method=RequestMethod.GET)
	public @ResponseBody RestResponse<Waf> wafLookup(HttpServletRequest request) {
		
		if (request.getParameter("name") == null) {
			log.info("Received REST request for WAF with name = " + request.getParameter("name") + ".");
		} else {
			log.info("Received REST request for WAF with a missing name parameter.");
		}

		String result = checkKey(request, LOOKUP);
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}
		
		if (request.getParameter("name") == null) {
			return RestResponse.failure(LOOKUP_FAILED);
		}
		
		Waf waf = wafService.loadWaf(request.getParameter("name"));
		
		if (waf == null) {
			log.warn("Invalid WAF Name.");
			return RestResponse.failure("Invalid WAF Name.");
		}
		return RestResponse.success(waf);
	}
	
	/**
	 * Returns the current set of rules from the WAF, generating new ones if none are present.
	 */
	@RequestMapping(headers="Accept=application/json", value="/{wafId}/rules", method=RequestMethod.GET)
	public @ResponseBody RestResponse<String> getRules(HttpServletRequest request,
			@PathVariable("wafId") int wafId) {
		log.info("Received REST request for rules from WAF with ID = " + wafId + ".");

		String result = checkKey(request, RULES);
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}
		
		Waf waf = wafService.loadWaf(wafId);
		
		if (waf == null) {
			log.warn("Invalid WAF ID.");
			return RestResponse.failure("Invalid WAF ID.");
		}
		wafService.generateWafRules(waf, waf.getLastWafRuleDirective());
		return RestResponse.success(wafService.getAllRuleText(waf));
	}
	
	@RequestMapping(headers="Accept=application/json", value="/new", method=RequestMethod.POST)
	public @ResponseBody RestResponse<Waf> newWaf(HttpServletRequest request) {
		log.info("Received REST request for a new WAF.");
		
		String result = checkKey(request, NEW);
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
		}
		
		String name = request.getParameter("name");
		String type = request.getParameter("type");
		
		if (name == null || type == null) {
			log.warn("Request for WAF creation failed because it was missing one or both parameters.");
			return RestResponse.failure(CREATION_FAILED);
		}
		
		WafType wafType = wafService.loadWafType(type);
		
		if (wafType == null) {
			log.warn("Invalid WAF type requested.");
			return RestResponse.failure(NOT_FOUND_WAF);
		}
		
		if (!name.trim().isEmpty() && name.length() < Waf.NAME_LENGTH) {
			
			Waf waf = new Waf();
			
			waf.setName(name);
			waf.setWafType(wafType);
			
			wafService.storeWaf(waf);
			return RestResponse.success(waf);
		} else {
			return RestResponse.failure(CREATION_FAILED);
		}
	}
	
	@RequestMapping(headers="Accept=application/json", value="/{wafId}/uploadLog", method=RequestMethod.POST)
	public @ResponseBody RestResponse uploadWafLog(HttpServletRequest request,
			@PathVariable("wafId") int wafId, @RequestParam("file") MultipartFile file) {
		log.info("Received REST request for a new WAF.");

		String result = checkKey(request, LOG);
		if (!result.equals(API_KEY_SUCCESS)) {
			return RestResponse.failure(result);
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
			return RestResponse.failure("Invalid input");
		}
				
		logParserService.setFileAsString(logContents);
		logParserService.setWafId(wafId);
		List<SecurityEvent> events = logParserService.parseInput();
		
		if (events == null || events.size() == 0) {
			log.debug("No Security Events found.");
		} else {
			log.debug("Found " + events.size() + " security events.");
		}
		
		return RestResponse.success(events);
	}
}
