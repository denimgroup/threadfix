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
import com.denimgroup.threadfix.data.entities.SecurityEvent;

public interface RPCService {
	
	/**
	 * Create an Application and return its ID.
	 * 
	 * @param name
	 * @param url
	 * @param organizationId
	 * @return
	 */
	public Integer createApplication(String name, String url, Integer organizationId);
	
	/**
	 * Create an ApplicationChannel gluing the ChannelType and Application together
	 * so that you can start to upload scans.
	 * 
	 * @param channelType
	 * @param applicationId
	 * @return
	 */
	public Integer addChannel(String channelType, Integer applicationId);
	
	/**
	 * Upload and run a scan on the proper channel.
	 * 
	 * @param channelId
	 * @param fileContents
	 * @param fileName
	 * @return
	 */
	public Integer runScan(Integer channelId, String fileContents);

	/**
	 * Check the scan to make sure there are no errors.
	 * 
	 * @param channelId
	 * @param fileContents
	 * @param fileName
	 * @return
	 */
	public String checkScan(Integer channelId, String fileContents);
	
	/**
	 * Add the WAF to the application and return true on success.
	 * 
	 * @param wafId
	 * @param applicationId
	 * @return
	 */
	public Boolean addWaf(Integer wafId, Integer applicationId);

	/**
	 * Create a new WAF and return its ID.
	 * 
	 * @param wafTypeName
	 * @param name
	 * @return
	 */
	public Integer createWaf(String wafTypeName, String name);

	/**
	 * Return the text from the appropriate WAF and using the correct directive (drop, deny, alert)
	 * 
	 * @param wafId
	 * @param directiveName
	 * @return
	 */
	public String pullWafRules(Integer wafId, String directiveName);
	
	/**
	 * Return a CSV separated string of rule ID and SecurityEvent count pairs.
	 * 
	 * @param wafId
	 * @return
	 */
	public String pullWafRuleStatistics(Integer wafId);

	/**
	 * Upload a WAF Log, parse it, and return the relevant SecurityEvents.
	 * 
	 * @param wafId
	 * @param logContents
	 * @return
	 */
	public List<SecurityEvent> uploadWafLog(String wafId, String logContents);
	
	/**
	 * Create an Organization and return its ID.
	 * 
	 * @param name
	 * @return
	 */
	public Integer createOrganization(String name);
}
