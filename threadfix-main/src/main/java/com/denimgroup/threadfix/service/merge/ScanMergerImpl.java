package com.denimgroup.threadfix.service.merge;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Service
public class ScanMergerImpl implements ScanMerger {
	
	private final SanitizedLogger log = new SanitizedLogger("ScanMergeService");
	
	private ChannelMerger channelMerger = new ChannelMerger();
	private ApplicationMerger applicationMerger = new ApplicationMerger();
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
	
		updateProjectRoot(applicationChannel, scan);
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

	private void updateProjectRoot(ApplicationChannel applicationChannel, Scan scan) {
		String projectRoot = ProjectRootParser.findOrParseProjectRoot(applicationChannel, scan);
		if (projectRoot != null && applicationChannel.getApplication() != null
				&& applicationChannel.getApplication().getProjectRoot() == null) {
			applicationChannel.getApplication().setProjectRoot(projectRoot);
			// TODO evaluate whether or not we need to do an application-wide surface location update
//			updateSurfaceLocation(applicationChannel.getApplication());
			updateSurfaceLocation(scan, projectRoot);
		}
	}
	
	private void updateSurfaceLocation(Scan scan, String newRoot) {
		if (scan == null || scan.getFindings() == null || newRoot == null
				|| newRoot.trim().equals(""))
			return;

		for (Finding finding : scan.getFindings()) {
			String newPath = StaticFindingPathUtils.getFindingPathWithRoot(finding, newRoot);
			if (newPath == null)
				continue;
			if (finding.getSurfaceLocation() != null)
				finding.getSurfaceLocation().setPath(newPath);
		}
	}
}
