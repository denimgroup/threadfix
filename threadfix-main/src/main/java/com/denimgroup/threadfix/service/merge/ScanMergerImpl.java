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
package com.denimgroup.threadfix.service.merge;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.translator.PathGuesser;

@Service
public class ScanMergerImpl implements ScanMerger {
	
	private final SanitizedLogger log = new SanitizedLogger("ScanMergerImpl");
	
	private ChannelMerger channelMerger = null;
	@Autowired private ApplicationMerger applicationMerger;
	@Autowired private ScanDao scanDao;
	@Autowired private VulnerabilityDao vulnerabilityDao;
	
	@Override
	public void merge(Scan scan, ApplicationChannel applicationChannel) {
		if (channelMerger == null) {
			channelMerger = new ChannelMerger(vulnerabilityDao);
		}
		
		if (scan.getFindings() != null && applicationChannel != null
				&& applicationChannel.getChannelType() != null
				&& applicationChannel.getChannelType().getName() != null) {
			log.info("The " + applicationChannel.getChannelType().getName()
					+ " import was successful" + " and found "
					+ scan.getFindings().size() + " findings.");
		}
	
		if (applicationChannel == null
				|| applicationChannel.getApplication() == null
				|| applicationChannel.getApplication().getId() == null) {
			log.error("An incorrectly configured application made it to processRemoteScan()");
			return;
		}
	
		PathGuesser.generateGuesses2(applicationChannel.getApplication(), scan);
		channelMerger.channelMerge(scan, applicationChannel);
		applicationMerger.applicationMerge(scan, applicationChannel.getApplication(), null);
	
		scan.setApplicationChannel(applicationChannel);
		scan.setApplication(applicationChannel.getApplication());
	
		if (scan.getNumberTotalVulnerabilities() != null
				&& scan.getNumberNewVulnerabilities() != null) {
			log.info(applicationChannel.getChannelType().getName()
					+ " scan completed processing with "
					+ scan.getNumberTotalVulnerabilities()
					+ " total Vulnerabilities ("
					+ scan.getNumberNewVulnerabilities() + " new).");
		} else {
			log.info(applicationChannel.getChannelType().getName()
					+ " scan completed.");
		}
	
		ScanCleanerUtils.clean(scan);
		scanDao.saveOrUpdate(scan);
	}
}
