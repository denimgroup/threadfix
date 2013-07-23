package com.denimgroup.threadfix.service.merge;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Service
public class ScanMergerImpl implements ScanMerger {
	
	private final SanitizedLogger log = new SanitizedLogger("ScanMergerImpl");
	
	private ChannelMerger channelMerger = new ChannelMerger();
	@Autowired private ApplicationMerger applicationMerger;
	@Autowired private ScanDao scanDao;
	
	public void merge(Scan scan, ApplicationChannel applicationChannel, ScanMergeConfiguration configuration) {
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
	
		PathGuesser.generateGuesses(configuration, scan);
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
