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
package com.denimgroup.threadfix.service.channel;

import org.springframework.beans.factory.annotation.Autowired;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;

/**
 * 
 * @author mcollins
 *
 */
public class ChannelImporterFactory {	
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	private ChannelSeverityDao channelSeverityDao = null;
	private ChannelTypeDao channelTypeDao = null;
	private GenericVulnerabilityDao genericVulnerabilityDao = null;
	private VulnerabilityMapLogDao vulnerabilityMapLogDao = null;
	
	/**
	 * @param channelTypeDao
	 * @param channelVulnerabilityDao
	 * @param channelSeverityDao
	 * @param genericVulnerabilityDao
	 * @param vulnerabilityMapLogDao
	 */
	@Autowired
	public ChannelImporterFactory(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, ChannelSeverityDao channelSeverityDao,
			GenericVulnerabilityDao genericVulnerabilityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		this.channelTypeDao = channelTypeDao;
		this.genericVulnerabilityDao = genericVulnerabilityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;
	}

	/**
	 * Returns a ChannelImporter implementation based on the channel name
	 * 
	 * @param applicationChannel
	 * @return
	 */
	public ChannelImporter getChannelImporter(ApplicationChannel applicationChannel) {

		if (applicationChannel == null || applicationChannel.getChannelType() == null
				|| applicationChannel.getChannelType().getName() == null
				|| applicationChannel.getChannelType().getName().trim().equals("")) {
			return null;
		}

		ChannelImporter channelImporter = null;
		String channelName = applicationChannel.getChannelType().getName();


		if (channelName.equals(ChannelType.ACUNETIX_WVS)){
			channelImporter = new AcunetixChannelImporter(channelTypeDao, channelVulnerabilityDao, 
					vulnerabilityMapLogDao, channelSeverityDao);
		} else if (channelName.equals(ChannelType.APPSCAN_DYNAMIC)) {
			channelImporter = new AppScanWebImporter(channelTypeDao, channelVulnerabilityDao,
					channelSeverityDao, genericVulnerabilityDao, vulnerabilityMapLogDao);
		} else if (channelName.equals(ChannelType.ARACHNI)){
			channelImporter = new ArachniChannelImporter(channelTypeDao, channelVulnerabilityDao, 
					vulnerabilityMapLogDao, channelSeverityDao);
		} else if (channelName.equals(ChannelType.BRAKEMAN)){
			channelImporter = new BrakemanChannelImporter(channelTypeDao, channelVulnerabilityDao, 
					vulnerabilityMapLogDao, channelSeverityDao);
		} else if (channelName.equals(ChannelType.BURPSUITE)) {
			channelImporter = new BurpSuiteChannelImporter(channelTypeDao, channelVulnerabilityDao, 
					vulnerabilityMapLogDao, channelSeverityDao);
		} else if (channelName.equals(ChannelType.CAT_NET)) {
			channelImporter = new CatNetChannelImporter(channelTypeDao, channelVulnerabilityDao,
						channelSeverityDao, vulnerabilityMapLogDao);
		} else if (channelName.equals(ChannelType.FINDBUGS)){
			channelImporter = new FindBugsChannelImporter(channelTypeDao, channelVulnerabilityDao, 
					vulnerabilityMapLogDao, channelSeverityDao);
		} else if (channelName.equals(ChannelType.FORTIFY)) {
			channelImporter = new FortifyChannelImporter(channelTypeDao, channelVulnerabilityDao,
					channelSeverityDao, genericVulnerabilityDao, vulnerabilityMapLogDao);
		} else if (channelName.equals(ChannelType.NESSUS)){
			channelImporter = new NessusChannelImporter(channelTypeDao, channelVulnerabilityDao, 
					vulnerabilityMapLogDao, channelSeverityDao);
		} else if (channelName.equals(ChannelType.NETSPARKER)) {
			channelImporter = new NetsparkerChannelImporter(channelTypeDao, channelVulnerabilityDao, 
					vulnerabilityMapLogDao, channelSeverityDao);
		} else if (channelName.equals(ChannelType.SKIPFISH)) {
			channelImporter = new SkipfishChannelImporter(channelTypeDao, channelVulnerabilityDao,
					channelSeverityDao, vulnerabilityMapLogDao);
		} else if (channelName.equals(ChannelType.W3AF)) {
			channelImporter = new W3afChannelImporter(channelTypeDao, channelVulnerabilityDao,
					channelSeverityDao, vulnerabilityMapLogDao);
		} else if (channelName.equals(ChannelType.WEBINSPECT)) {
			channelImporter = new WebInspectChannelImporter(channelTypeDao, channelVulnerabilityDao,
					channelSeverityDao, vulnerabilityMapLogDao);
		} else if (channelName.equals(ChannelType.ZAPROXY)){
			channelImporter = new ZaproxyChannelImporter(channelTypeDao, channelVulnerabilityDao, 
					vulnerabilityMapLogDao, channelSeverityDao);
		} else {
			return null;
		}
		
		if (channelImporter != null)
			channelImporter.setChannel(applicationChannel);

		return channelImporter;
	}
	
}