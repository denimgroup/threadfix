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
package com.denimgroup.threadfix.service;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.dao.WafTypeDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.data.entities.WafType;

@Service
@Transactional(readOnly = false)
public class RPCServiceImpl implements RPCService {
	
	private final Log log = LogFactory.getLog(RPCServiceImpl.class);
	
	private OrganizationDao organizationDao;
	private ApplicationDao applicationDao;
	private ChannelTypeDao channelTypeDao;
	private ApplicationChannelDao applicationChannelDao;
	private ScanMergeService scanMergeService;
	private WafService wafService;
	private WafTypeDao wafTypeDao;
	private LogParserService logParserService;
	private WafRuleDirectiveDao wafRuleDirectiveDao;
	private ScanService scanService;
	
	@Autowired
	public RPCServiceImpl(OrganizationDao organizationDao, ApplicationDao applicationDao, 
			ChannelTypeDao channelTypeDao, ApplicationChannelDao applicationChannelDao,
			ScanMergeService scanMergeService, WafService wafService, WafTypeDao wafTypeDao, 
			LogParserService logParserService, WafRuleDirectiveDao wafRuleDirectiveDao,
			ScanService scanService) {
		this.organizationDao = organizationDao;
		this.applicationDao = applicationDao;
		this.channelTypeDao = channelTypeDao;
		this.applicationChannelDao = applicationChannelDao;
		this.scanMergeService = scanMergeService;
		this.wafService = wafService;
		this.wafTypeDao = wafTypeDao;
		this.logParserService = logParserService;
		this.wafRuleDirectiveDao = wafRuleDirectiveDao;
		this.scanService = scanService;
	}

	public Integer createApplication(String name, String url, Integer organizationId){
		if (name == null || name.isEmpty() || name.length() > Application.NAME_LENGTH ||
				url == null || url.isEmpty() || url.length() > Application.URL_LENGTH ||
				organizationId == null) {
			log.warn("Invalid input to createApplication()");
    		return null;
		}
		
		Organization organization = organizationDao.retrieveById(organizationId);
		if (organization == null) {
			log.warn("Invalid input to createApplication()");
			return null;
		}
				
		Application databaseApplication = applicationDao.retrieveByName(name);
		
		if (databaseApplication != null) {
			if (databaseApplication.getOrganization().getId().equals(organizationId)) {
				log.warn("An application named " + name + " already existed, returning current ID.");
				return databaseApplication.getId();
			} else {
				log.warn("An application from a different Organization was requested. Returning null.");
				return null;
			}
		}

		Application application = new Application();
		application.setName(name);
		application.setUrl(url);
		application.setOrganization(organization);
		applicationDao.saveOrUpdate(application);
		log.info("New application was successfully created with the name " + name + " under the organization " + organization.getName() + ".");
		return application.getId();
	}
	
	public Integer addChannel(String channelType, Integer applicationId) {
		if (channelType == null || applicationId == null) {
			log.warn("Invalid input to addChannel()");
			return null;
		}
		
		ChannelType type = channelTypeDao.retrieveByName(channelType);
		Application application = applicationDao.retrieveById(applicationId);
		if (type == null || application == null) {
			log.warn("Invalid input to addChannel()");
			return null;
		}
		
		ApplicationChannel applicationChannel = applicationChannelDao.retrieveByAppIdAndChannelId(applicationId, type.getId());
		if (applicationChannel != null) {
			log.info("Returning existing ApplicationChannel ID.");
			return applicationChannel.getId();
		}
			
		applicationChannel = new ApplicationChannel();
		
		applicationChannel.setApplication(application);
		applicationChannel.setChannelType(type);
		
		applicationChannelDao.saveOrUpdate(applicationChannel);
		
		log.info(channelType + " was successfully added to Application " + application.getName() + ".");
		return applicationChannel.getId();
	}
	
	@Override
	public String checkScan(Integer channelId, String fileContents) {
		String result = scanService.checkRPCFile(channelId, fileContents);
		log.debug(result);
		return result;
	}

	@Override
	public Integer runScan(Integer channelId, String fileContents) {
		if (channelId == null || fileContents == null) {
			log.warn("Invalid input to runScan()");
			return null;
		}
		Integer scanId = scanMergeService.saveRPCScanAndRun(channelId, fileContents);
		
		if (scanId != null) {
			log.info("Scan ID = " + scanId);
		} else {
			log.warn("Scan failure.");
		}
		
		return scanId;
	}

	@Override
	public Integer createWaf(String wafTypeName, String name) {
		if (wafTypeName == null || name == null || name.isEmpty() || name.length() > Waf.NAME_LENGTH) {
			log.warn("Invalid input to createWaf()");
			return null;
		}
		
		Waf waf = wafService.loadWaf(name);
		if (waf != null) {
			log.info("A WAF named " + name + " already existed, returning existing ID.");
			return waf.getId();
		}
		
		WafType wafType = wafTypeDao.retrieveByName(wafTypeName);
		if (wafType == null) {
			log.warn("Invalid wafTypeName for createWaf()");
			return null;
		}
		
		waf = new Waf();
		waf.setName(name);
		waf.setWafType(wafType);
		
		wafService.storeWaf(waf);
		
		log.info("WAF correctly created with the name " + waf.getName() + ".");
		return waf.getId();
	}
	
	@Override
	public Boolean addWaf(Integer wafId, Integer applicationId) {
		if (wafId == null || applicationId == null) {
			log.warn("Invalid input to addWaf()");
			return false;
		}
		
		Waf waf = wafService.loadWaf(wafId);
		Application application = applicationDao.retrieveById(applicationId);
		if (waf == null || application == null) {
			log.warn("Invalid input to addWaf()");
			return false;
		}
				
		if (waf.getApplications() == null)
			waf.setApplications(new ArrayList<Application>());

		if (application.getWaf() != null && application.getWaf().getId().equals(waf.getId())) {
			log.info("The application " + application.getName() + " already had the WAF " + waf.getName() + ".");
			return true;
		}
		
		waf.getApplications().add(application);
		wafService.storeWaf(waf);
		
		application.setWaf(waf);
		applicationDao.saveOrUpdate(application);
		
		log.info("The WAF " + waf.getName() + " was added to the application " + application.getName() + ".");
		return true;
	}

	@Override
	public String pullWafRules(Integer wafId, String directiveName) {
		if (wafId == null) {
			log.warn("pullWafRules() received a null ID.");
			return null;
		}
		
		Waf waf = wafService.loadWaf(wafId);
		if (waf == null || waf.getWafType() == null || waf.getWafType().getId() == null) {
			log.warn("Invalid WAF configuration.");
			return null;
		}
		
		WafRuleDirective directive = wafRuleDirectiveDao.retrieveByWafTypeIdAndDirective(waf.getWafType(), directiveName);
				
		wafService.generateWafRules(waf, directive);
		
		StringBuffer buffer = new StringBuffer();
		
		boolean added = false;
		
		if (waf.getWafRules() != null){
			for (WafRule wafRule : waf.getWafRules()) {
				if (wafRule != null && wafRule.getRule() != null) {
					added = true;
					buffer.append(wafRule.getRule()).append('\n');
				}
			}
		}
				
		if (added) {
			log.info("WAF rules were generated properly from WAF " + waf.getName() + ".");
		} else {
			log.warn("The WAF didn't have any valid rules.");
		}
		return buffer.toString();
	}

	@Override
	public String pullWafRuleStatistics(Integer wafId) {
		if (wafId == null || wafService.loadWaf(wafId) == null) {
			log.warn("Invalid input.");
			return "Invalid input.";
		}
		
		Waf waf = wafService.loadWaf(wafId);
		
		List<WafRule> rules = waf.getWafRules();

		StringBuffer buffer = new StringBuffer();
		
		if (rules == null || rules.size() == 0) {
			log.warn("No rules were present.");
			return "WAF had no rules.";
		}
		
		for (WafRule rule : rules) {
			if (rule == null || rule.getNativeId() == null)
				continue;
			List<SecurityEvent> events = rule.getSecurityEvents();
			if (events == null)
				events = new ArrayList<SecurityEvent>();
			
			buffer.append(rule.getNativeId()).append(',').append(events.size()).append(',');
		}
		
		String returnString = buffer.toString();
		
		if (returnString.endsWith(","))
			returnString = returnString.substring(0, returnString.length() - 1);
		
		log.info("Correctly generated WAF Rule Statistics for WAF " + waf.getName() + ".");
		return returnString;
	}

	@Override
	public List<SecurityEvent> uploadWafLog(String wafId, String logContents) {
		if (wafId == null || wafId.isEmpty() || logContents == null || logContents.isEmpty()) {
			log.debug("Invalid input.");
			return null;
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

	@Override
	public Integer createOrganization(String name) {
		if (name == null || name.isEmpty() || name.length() > Organization.NAME_LENGTH) {
			log.debug("Invalid input to createOrganization()");
			return null;
		}
		
		Organization organization = organizationDao.retrieveByName(name);
		
		if (organization != null) {
			log.debug("An Organization named " + organization.getName() + " already existed, returning existing ID.");
		} else {
			organization = new Organization();
			organization.setName(name);
			organizationDao.saveOrUpdate(organization);
			if (organization.getId() != null) {
				log.debug("Created new Organization with the name " + name + ".");
			} else {
				log.debug("Failed to create a new Organization named " + name + ".");
			}
		}

		return organization.getId();
	}
}
