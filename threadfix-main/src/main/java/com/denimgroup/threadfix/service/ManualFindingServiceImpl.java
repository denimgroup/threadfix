package com.denimgroup.threadfix.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.merge.ApplicationMerger;
import com.denimgroup.threadfix.service.merge.ScanCleanerUtils;

@Service
public class ManualFindingServiceImpl implements ManualFindingService {
	private final SanitizedLogger log = new SanitizedLogger("ScanMergeService");
	
	private ApplicationMerger applicationMerger = null;
	private ScanDao scanDao = null;
	private ChannelTypeDao channelTypeDao = null;
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	private ChannelSeverityDao channelSeverityDao = null;
	private ApplicationChannelDao applicationChannelDao = null;
	private ApplicationDao applicationDao = null;
	private UserDao userDao = null;
	private VulnerabilityDao vulnerabilityDao = null;

	@Autowired
	public ManualFindingServiceImpl(ScanDao scanDao, ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao,
			ApplicationChannelDao applicationChannelDao,
			ApplicationDao applicationDao,
			UserDao userDao,
			VulnerabilityDao vulnerabilityDao,
			ApplicationMerger applicationMerger) {
		this.scanDao = scanDao;
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		this.applicationChannelDao = applicationChannelDao;
		this.applicationDao = applicationDao;
		this.userDao = userDao;
		this.vulnerabilityDao = vulnerabilityDao;
		this.applicationMerger = applicationMerger;
	}
	
	/**
	 * Handle the Manual Finding edit submission. 
	 * It's a wrapper around the normal process manual finding method.
	 */
	@Override
	@Transactional(readOnly = false)
	public boolean processManualFindingEdit(Finding finding, Integer applicationId) {
		boolean result = processManualFinding(finding, applicationId);
		if (result && finding != null && finding.getScan() != null && 
				finding.getScan().getFindings() != null) {
			
			finding.getScan().setNumberTotalVulnerabilities(
					finding.getScan().getNumberTotalVulnerabilities() - 1);
			
			Finding oldFinding = null;

			int id = finding.getId();
			for (Finding scanFinding : finding.getScan().getFindings()) {
				if (scanFinding != finding && scanFinding.getId().equals(id)) {
					oldFinding = scanFinding;
				}
			}
			
			if (oldFinding != null) {
				finding.getScan().getFindings().remove(oldFinding);
				if (oldFinding.getVulnerability() != null && 
						oldFinding.getVulnerability().getFindings() != null) {
					Vulnerability vuln = oldFinding.getVulnerability();
					vuln.getFindings().remove(oldFinding);
					if (vuln.getFindings().size() == 0) {
						vuln.getApplication().getVulnerabilities().remove(vuln);
						vuln.setApplication(null);
						vulnerabilityDao.delete(vuln);
					}
				}
				vulnerabilityDao.evict(oldFinding);
			}
		}
		return result;
	}
	
	@Override
	@Transactional(readOnly = false)
	public boolean processManualFinding(Finding finding, Integer applicationId) {
		if (finding == null || applicationId == null) {
			log.debug("Null input to processManualFinding");
			return false;
		}
		
		ChannelType manualChannelType = channelTypeDao.retrieveByName(ScannerType.MANUAL.getFullName());

		Scan scan = getManualScan(applicationId);
		if (scan == null || scan.getApplicationChannel() == null
				|| scan.getApplication() == null || scan.getFindings() == null) {
			log.debug("processManualFinding could not find or create the necessary manual scan.");
			return false;
		}

		String userName = SecurityContextHolder.getContext()
				.getAuthentication().getName();
		
		User user = userDao.retrieveByName(userName);
		finding.setUser(user);

		// Set the channelVulnerability
		ChannelVulnerability channelVulnerability = channelVulnerabilityDao
				.retrieveByCode(manualChannelType,
						finding.getChannelVulnerability().getCode());
		finding.setChannelVulnerability(channelVulnerability);

		if (finding.getChannelSeverity() != null &&
				finding.getChannelSeverity().getId() != null) {
			// Set the channelSeverity so we can get the corresponding
			// genericSeverity when appMerge is called.
			ChannelSeverity channelSeverity = channelSeverityDao
					.retrieveById(finding.getChannelSeverity().getId());
			finding.setChannelSeverity(channelSeverity);
		} else {
			ChannelSeverity channelSeverity = channelSeverityDao
					.retrieveByCode(manualChannelType, GenericSeverity.MEDIUM);
			finding.setChannelSeverity(channelSeverity);
		}

		if (!finding.getIsStatic()) {
			finding.setDataFlowElements(null);
		} else {
			String path = finding.getSurfaceLocation().getPath();
			if (path != null
					&& scan.getApplication().getProjectRoot() != null
					&& scan.getApplication().getProjectRoot().toLowerCase() != null
					&& path.toLowerCase().contains(
							scan.getApplication().getProjectRoot()
									.toLowerCase())) {
				path = path.substring(path.toLowerCase().indexOf(
						scan.getApplication().getProjectRoot().toLowerCase()));
			}
			finding.getSurfaceLocation().setPath(path);
		}

		Scan tempScan = new Scan();
		tempScan.setFindings(new ArrayList<Finding>());
		tempScan.getFindings().add(finding);
		applicationMerger.applicationMerge(tempScan, applicationId, null);

		scan.getFindings().add(finding);
		scan.setNumberTotalVulnerabilities(scan.getNumberTotalVulnerabilities() + 1);
		finding.setScan(scan);
		ScanCleanerUtils.clean(scan);
		scanDao.saveOrUpdate(scan);
		log.debug("Manual Finding submission was successful.");
		log.debug(userName + " has added a new finding to the Application " + 
				finding.getScan().getApplication().getName());
		return true;
	}

	private Scan getManualScan(Integer applicationId) {
		if (applicationId == null)
			return null;

		ApplicationChannel applicationChannel = null;
		ChannelType manualChannel = channelTypeDao
				.retrieveByName(ScannerType.MANUAL.getFullName());
		if (manualChannel != null)
			applicationChannel = applicationChannelDao
					.retrieveByAppIdAndChannelId(applicationId,
							manualChannel.getId());

		if (applicationChannel != null
				&& applicationChannel.getScanList() != null
				&& applicationChannel.getScanList().size() != 0) {
			return applicationChannel.getScanList().get(0);
		}

		Scan newManualScan = initializeNewManualScan(applicationId);

		if (applicationChannel == null)
			applicationChannel = createManualApplicationChannel(applicationId);

		if (applicationChannel == null)
			return null;

		newManualScan.setApplicationChannel(applicationChannel);

		return newManualScan;
	}

	private Scan initializeNewManualScan(Integer applicationId) {
		if (applicationId == null)
			return null;

		Application application = applicationDao.retrieveById(applicationId);
		if (application == null)
			return null;

		Scan scan = new Scan();
		scan.setApplication(application);

		List<Finding> findingList = new ArrayList<>();
		scan.setFindings(findingList);

		scan.setNumberNewVulnerabilities(0);
		scan.setNumberOldVulnerabilities(0);
		scan.setNumberClosedVulnerabilities(0);
		scan.setNumberTotalVulnerabilities(0);
		scan.setNumberResurfacedVulnerabilities(0);
		scan.setNumberOldVulnerabilitiesInitiallyFromThisChannel(0);

		return scan;
	}

	private ApplicationChannel createManualApplicationChannel(
			Integer applicationId) {
		if (applicationId == null)
			return null;

		Application application = applicationDao.retrieveById(applicationId);
		if (application == null) {
			return null;
		}

		ApplicationChannel applicationChannel = new ApplicationChannel();
		applicationChannel.setApplication(application);
		ChannelType manualChannel = channelTypeDao
				.retrieveByName(ScannerType.MANUAL.getFullName());
		applicationChannel.setChannelType(manualChannel);

		if (application.getChannelList() == null)
			application.setChannelList(new ArrayList<ApplicationChannel>());

		application.getChannelList().add(applicationChannel);
		applicationChannelDao.saveOrUpdate(applicationChannel);
		applicationDao.saveOrUpdate(application);
		return applicationChannel;
	}
}
