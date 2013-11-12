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
package com.denimgroup.threadfix.plugin.scanner;

import java.util.Collection;

import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.plugin.scanner.service.channel.ChannelImporter;

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
		
		Collection<? extends ChannelImporter> importers = ScannerPluginLoader.getScannerPlugins();
		ChannelImporter channelImporter = null;
		String channelName = applicationChannel.getChannelType().getName();
		for (ChannelImporter importer: importers) {
			if (importer.getType().equals(channelName)) {
				channelImporter = importer;
			}
		}
		
		if (channelImporter != null) {
			channelImporter.setChannel(applicationChannel);
		}

		return channelImporter;
	}
	
}
