////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.channel;

import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;

/**
 * 
 * @author mcollins
 *
 */
public class ChannelImporterFactory {
	
	private ChannelImporterFactory(){}
	
	/**
	 * Returns a ChannelImporter implementation based on the channel name
	 * 
	 * @param applicationChannel
	 * @return
	 */
	@Transactional
	public static ChannelImporter getChannelImporter(ApplicationChannel applicationChannel) {

		if (applicationChannel == null || applicationChannel.getChannelType() == null
				|| applicationChannel.getChannelType().getName() == null
				|| applicationChannel.getChannelType().getName().trim().equals("")) {
			return null;
		}

		ChannelImporter channelImporter = null;
		String channelName = applicationChannel.getChannelType().getName();

		switch (channelName) {
			case ChannelType.ACUNETIX_WVS:
				channelImporter = new AcunetixChannelImporter();          break;
			case ChannelType.APPSCAN_DYNAMIC:
				channelImporter = new AppScanWebImporter();               break;
			case ChannelType.APPSCAN_ENTERPRISE:
				channelImporter = new AppScanEnterpriseChannelImporter(); break;
			case ChannelType.APPSCAN_SOURCE:
				channelImporter = new AppScanSourceChannelImporter();     break;
			case ChannelType.ARACHNI:
				channelImporter = new ArachniChannelImporter();           break;
			case ChannelType.BRAKEMAN:
				channelImporter = new BrakemanChannelImporter();          break;
			case ChannelType.BURPSUITE:
				channelImporter = new BurpSuiteChannelImporter();         break;
			case ChannelType.CAT_NET:
				channelImporter = new CatNetChannelImporter();            break;
			case ChannelType.FINDBUGS:
				channelImporter = new FindBugsChannelImporter();          break;
			case ChannelType.FORTIFY:
				channelImporter = new FortifyChannelImporter();           break;
			case ChannelType.NESSUS:
				channelImporter = new NessusChannelImporter();            break;
			case ChannelType.NETSPARKER:
				channelImporter = new NetsparkerChannelImporter();        break;
			case ChannelType.NTO_SPIDER:
				channelImporter = new NTOSpiderChannelImporter();         break;
			case ChannelType.SKIPFISH:
				channelImporter = new SkipfishChannelImporter();          break;
			case ChannelType.W3AF:
				channelImporter = new W3afChannelImporter();              break;
			case ChannelType.WEBINSPECT:
				channelImporter = new WebInspectChannelImporter();        break;
			case ChannelType.ZAPROXY:
				channelImporter = new ZaproxyChannelImporter();           break;
			case ChannelType.DEPENDENCY_CHECK:
				channelImporter = new DependencyCheckChannelImporter();   break;
			case ChannelType.MANUAL:
				channelImporter = new SSVLChannelImporter();              break;
		}
		
		if (channelImporter != null) {
			channelImporter.setChannel(applicationChannel);
		}

		return channelImporter;
	}
	
}
