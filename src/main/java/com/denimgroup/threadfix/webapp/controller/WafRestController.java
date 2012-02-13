package com.denimgroup.threadfix.webapp.controller;

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.LogParserService;
import com.denimgroup.threadfix.service.WafService;

@Controller
@RequestMapping("/rest/wafs")
public class WafRestController extends RestController {
	
	public static final String CREATION_FAILED = "New WAF creation failed.";
	public static final String LOOKUP_FAILED = "WAF Lookup failed.";
	
	private WafService wafService;
	private LogParserService logParserService;
	
	@Autowired
	public WafRestController(APIKeyService apiKeyService, 
			WafService wafService, LogParserService logParserService) {
		this.apiKeyService = apiKeyService;
		this.wafService = wafService;
		this.logParserService = logParserService;
	}
	
	// TODO figure out if there is an easier way to make Spring respond to both
	@RequestMapping(headers="Accept=application/json", value="", method=RequestMethod.GET)
	public @ResponseBody Object wafIndexNoSlash(HttpServletRequest request) {
		return wafIndex(request);
	}
	
	@RequestMapping(headers="Accept=application/json", value="/", method=RequestMethod.GET)
	public @ResponseBody Object wafIndex(HttpServletRequest request) {
		log.info("Received REST request for WAFs");

		if (!checkKey(request)) {
			return API_KEY_ERROR;
		}
		
		List<Waf> wafs = wafService.loadAll();
		
		if (wafs == null) {
			log.warn("wafService.loadAll() returned null.");
		}
		return wafs;
	}
	
	@RequestMapping(headers="Accept=application/json", value="/{wafId}", method=RequestMethod.GET)
	public @ResponseBody Object wafDetail(HttpServletRequest request,
			@PathVariable("wafId") int wafId) {
		log.info("Received REST request for WAF with ID = " + wafId + ".");

		if (!checkKey(request)) {
			return API_KEY_ERROR;
		}
		
		Waf waf = wafService.loadWaf(wafId);
		
		if (waf == null) {
			log.warn("Invalid WAF ID.");
			return LOOKUP_FAILED;
		}
		return waf;
	}
	
	/**
	 * Returns the current set of rules from the WAF, generating new ones if none are present.
	 * @param request
	 * @param wafId
	 * @return
	 */
	@RequestMapping(headers="Accept=application/json", value="/{wafId}/rules", method=RequestMethod.GET)
	public @ResponseBody Object getRules(HttpServletRequest request,
			@PathVariable("wafId") int wafId) {
		log.info("Received REST request for rules from WAF with ID = " + wafId + ".");

		if (!checkKey(request)) {
			return API_KEY_ERROR;
		}
		
		Waf waf = wafService.loadWaf(wafId);
		
		if (waf == null) {
			log.warn("Invalid WAF ID.");
			return LOOKUP_FAILED;
		}
		wafService.generateWafRules(waf, waf.getLastWafRuleDirective());
		return waf.getWafRules();
	}
	
	@RequestMapping(headers="Accept=application/json", value="/new", method=RequestMethod.POST)
	public @ResponseBody Object newWaf(HttpServletRequest request) {
		log.info("Received REST request for a new WAF.");
		
		if (!checkKey(request)) {
			return API_KEY_ERROR;
		}
		
		String name = request.getParameter("name");
		String type = request.getParameter("type");
		
		if (name == null || type == null) {
			log.warn("Request for WAF creation failed because it was missing one or both parameters.");
			return CREATION_FAILED;
		}
		
		WafType wafType = wafService.loadWafType(type);
		
		if (wafType == null) {
			log.warn("Invalid WAF type requested.");
			return CREATION_FAILED;
		}
		
		if (name != null && !name.trim().isEmpty() && name.length() < Waf.NAME_LENGTH) {
			
			Waf waf = new Waf();
			
			waf.setName(name);
			waf.setWafType(wafType);
			
			wafService.storeWaf(waf);
			return waf;
		} else {
			return CREATION_FAILED;
		}
	}
	
	// TODO flesh out
	@RequestMapping(headers="Accept=application/json", value="/{wafId}/uploadLog", method=RequestMethod.POST)
	public @ResponseBody Object uploadWafLog(HttpServletRequest request, 
			@PathVariable("wafId") int wafId, @RequestParam("file") MultipartFile file) {
		log.info("Received REST request for a new WAF.");

		if (!checkKey(request)) {
			return API_KEY_ERROR;
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
			return "Invalid input";
		}
				
		logParserService.setFileAsString(logContents);
		logParserService.setWafId(Integer.valueOf(wafId));
		List<SecurityEvent> events = logParserService.parseInput();
		
		if (events == null || events.size() == 0) {
			log.debug("No Security Events found.");
		} else {
			log.debug("Found " + events.size() + " security events.");
		}
		
		return events;
	}
}
