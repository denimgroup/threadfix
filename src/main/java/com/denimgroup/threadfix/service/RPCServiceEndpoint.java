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

import java.util.List;

import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.jws.soap.SOAPBinding.Style;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.service.channel.ChannelImporter;

@WebService(serviceName="RPCService")
@SOAPBinding(style=Style.RPC)
public class RPCServiceEndpoint extends SpringBeanAutowiringSupport {

	protected static Log log = LogFactory.getLog(RPCServiceEndpoint.class);
	
	private static final String AUTHENTICATION_FAILURE = "Key authentication failed.";
	private static final String NULL_INPUT = "Null Input.";
	
    private RPCService rpcService;
    private APIKeyService apiKeyService;
	
	@Autowired
	public RPCServiceEndpoint(RPCService rpcService, APIKeyService apiKeyService) {
		this.rpcService = rpcService;
		this.apiKeyService = apiKeyService;
	}
    
    @WebMethod
    public String createApplication(String apiKey, String name, String url, Integer organizationId){
    	log.info("Received RPC request for createApplication()");
    	
    	if (!checkKey(apiKey))
    		return AUTHENTICATION_FAILURE;
    	if (name == null || url == null || organizationId == null)
    		return NULL_INPUT;
    	Integer returnValue = rpcService.createApplication(name, url, organizationId);
    	if (returnValue == null)
    		return "Application Creation failed.";
    	else
    		return returnValue.toString();
    }
    
    @WebMethod
    public String createOrganization(String apiKey, String name){
    	log.info("Received RPC request for createOrganization()");
    	
    	if (!checkKey(apiKey))
    		return AUTHENTICATION_FAILURE;
    	if (name == null || name.isEmpty())
    		return NULL_INPUT;
    	Integer returnValue = rpcService.createOrganization(name);
    	if (returnValue == null)
    		return "Organization Creation failed.";
    	else
    		return returnValue.toString();
    }
    
    @WebMethod
    public String addChannel(String apiKey, String channelType, Integer applicationId){
    	log.info("Received RPC request for addChannel()");
    	
    	if (!checkKey(apiKey))
    		return AUTHENTICATION_FAILURE;
    	if (channelType == null || applicationId == null)
    		return NULL_INPUT;
    	Integer returnValue = rpcService.addChannel(channelType, applicationId);
    	if (returnValue == null)
    		return "Channel Creation failed.";
    	else
    		return returnValue.toString();
    }
    
    @WebMethod
    public String runScan(String apiKey, Integer channelId, String scanData){
    	log.info("Received RPC request for runScan()");
    	
    	if (!checkKey(apiKey))
    		return AUTHENTICATION_FAILURE;
    	if (channelId == null || scanData == null)
    		return NULL_INPUT;
    	Integer id = null;
    	String returnValue = rpcService.checkScan(channelId, scanData);
    	if (ChannelImporter.SUCCESSFUL_SCAN.equals(returnValue)) {
	    	id = rpcService.runScan(channelId, scanData);
	    	if (id == null)
	    		return "Scan upload failed.";
	    	else
	    		return id.toString();
    	} else {
    		return returnValue;
    	}
    }
    
    @WebMethod
    public String createWaf(String apiKey, String wafType, String name){
    	log.info("Received RPC request for createWaf()");
    	
    	if (!checkKey(apiKey))
    		return AUTHENTICATION_FAILURE;
    	if (wafType == null || name == null)
    		return NULL_INPUT;
    	Integer id = rpcService.createWaf(wafType, name);
    	if (id == null)
    		return "WAF Creation failed.";
    	else
    		return id.toString();
    }
    
    @WebMethod
    public String addWaf(String apiKey, Integer wafId, Integer applicationId){
    	log.info("Received RPC request for addWaf()");
    	
    	if (!checkKey(apiKey))
    		return AUTHENTICATION_FAILURE;
    	if (wafId == null || applicationId == null)
    		return NULL_INPUT;
    	boolean result = rpcService.addWaf(wafId, applicationId);
    	if (result)
    		return "Adding WAF succeeded.";
    	else
    		return "Adding WAF failed.";
    }
    
    @WebMethod
    public String pullWafRules(String apiKey, Integer wafId, String directiveName){
    	log.info("Received RPC request for pullWafRules()");
    	
    	if (!checkKey(apiKey))
    		return AUTHENTICATION_FAILURE;
    	if (wafId == null)
    		return NULL_INPUT;
    	String result = rpcService.pullWafRules(wafId, directiveName);
    	if (result != null) {
    		return result;
    	} else {
    		log.debug("Pulling WAF Rules Failed.");
    		return "Pulling WAF Rules Failed.";
    	}
    }
    
    @WebMethod
    public String uploadWafLog(String apiKey, String wafId, String logContents){
    	log.info("Received RPC request for uploadWafLog()");
    	
    	if (!checkKey(apiKey))
    		return AUTHENTICATION_FAILURE;
    	if (logContents == null)
    		return NULL_INPUT;
    	List<SecurityEvent> events = rpcService.uploadWafLog(wafId, logContents);
    	if (events != null)
    		return String.valueOf(events.size());
    	else
    		return "Uploading WAF Log failed.";
    }
    
    @WebMethod
    public String pullWafRuleStatistics(String apiKey, Integer wafId){
    	log.info("Received RPC request for pullWafRuleStatistics()");
    	
    	if (!checkKey(apiKey))
    		return AUTHENTICATION_FAILURE;
    	if (wafId == null)
    		return NULL_INPUT;
    	String result = rpcService.pullWafRuleStatistics(wafId);
    	if (result != null)
    		return result;
    	else
    		return "Pulling WAF Rule Statistics Failed.";
    }
    
    private boolean checkKey(String apiKey) {
    	boolean authentic = apiKeyService.checkKey(apiKey);
    	
    	if (authentic)
    		log.info("API key " + apiKey + " authenticated successfully.");
    	else
    		log.warn("API key " + apiKey + " did not authenticate successfully.");
    	
    	return authentic;
    }

}