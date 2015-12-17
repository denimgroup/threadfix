////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.merge.ApplicationMerger;
import com.denimgroup.threadfix.service.merge.ScanCleanerUtils;
import org.apache.commons.validator.routines.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.listOf;

@Service
public class ManualFindingServiceImpl implements ManualFindingService {
	private final SanitizedLogger log = new SanitizedLogger("ScanMergeService");

    @Autowired
	private ApplicationMerger applicationMerger;
    @Autowired
	private ScanDao scanDao;
    @Autowired
	private ChannelTypeDao channelTypeDao;
    @Autowired
	private ChannelVulnerabilityDao channelVulnerabilityDao;
    @Autowired
	private ChannelSeverityDao channelSeverityDao;
    @Autowired
	private ApplicationChannelDao applicationChannelDao;
    @Autowired
	private ApplicationDao applicationDao;
    @Autowired
	private UserDao userDao;
    @Autowired
	private VulnerabilityDao vulnerabilityDao;
    @Autowired
    private VulnerabilityService vulnerabilityService;
    @Autowired
    private ScanCleanerUtils scanCleanerUtils;
	
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

        vulnerabilityService.updateVulnerabilityReport(
                applicationDao.retrieveById(applicationId));

		return result;
	}
	
	@Override
	@Transactional(readOnly = false)
	public boolean processManualFinding(Finding finding, Integer applicationId) {
		if (finding == null || applicationId == null) {
			log.debug("Null input to processManualFinding");
			return false;
		}
		
		ChannelType manualChannelType = channelTypeDao.retrieveByName(ScannerType.MANUAL.getDisplayName());

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

		if (finding.getSurfaceLocation() == null) {
			finding.setSurfaceLocation(new SurfaceLocation());
		}

		String path = finding.getSurfaceLocation().getPath();

		if (!finding.getIsStatic()) {
			finding.setDataFlowElements(null);

			if (path != null && UrlValidator.getInstance().isValid(path)) {
				try {
					finding.getSurfaceLocation().setUrl(new URL(path));
				} catch (MalformedURLException e) {
					throw new RestIOException(e, "Encountered URL Formatting error.");
				}
			}
		} else {

			// this code is intended to set the path properly when the user imports static scans
			// from different source folders
			// this has been largely replaced by HAM.
			// TODO consider removing this code
			if (path != null
					&& scan.getApplication().getProjectRoot() != null
					&& path.toLowerCase().contains(
							scan.getApplication().getProjectRoot()
									.toLowerCase())) {
				path = path.substring(path.toLowerCase().indexOf(
						scan.getApplication().getProjectRoot().toLowerCase()));
				finding.getSurfaceLocation().setPath(path);
			}
		}

        if (finding.getIsStatic()) {
            finding.setCalculatedFilePath(finding.getDataFlowElements().get(0).getSourceFileName());
        } else {
            finding.setCalculatedUrlPath(finding.getSurfaceLocation().getPath());
		}

		Scan tempScan = new Scan();
		tempScan.setFindings(listOf(Finding.class));
		tempScan.getFindings().add(finding);
		finding.setScan(scan);
		applicationMerger.applicationMerge(tempScan, applicationId, null);

		scan.getFindings().add(finding);
		if (finding.getId() == null) {
			scan.setNumberTotalVulnerabilities(scan.getNumberTotalVulnerabilities() + 1);
		}

        switch (finding.getChannelSeverity().getCode()) {
            case GenericSeverity.CRITICAL:
                scan.setNumberCriticalVulnerabilities( scan.getNumberCriticalVulnerabilities() + 1 );
                break;
            case GenericSeverity.HIGH:
                scan.setNumberHighVulnerabilities(scan.getNumberHighVulnerabilities() + 1);
                break;
            case GenericSeverity.MEDIUM:
                scan.setNumberMediumVulnerabilities(scan.getNumberMediumVulnerabilities() + 1);
                break;
            case GenericSeverity.LOW:
                scan.setNumberLowVulnerabilities(scan.getNumberLowVulnerabilities() + 1);
                break;
            case GenericSeverity.INFO:
                scan.setNumberInfoVulnerabilities( scan.getNumberInfoVulnerabilities() + 1 );
                break;
        }

        scanCleanerUtils.clean(scan);

		// Randomly generate NativeId
		if (finding.getNativeId() == null || finding.getNativeId().isEmpty())
			finding.setNativeId(getRandomNativeId());

		vulnerabilityService.storeVulnerability(finding.getVulnerability());

		scanDao.saveOrUpdate(scan);
		log.debug("Manual Finding submission was successful.");
		log.debug(userName + " has added a new finding to the Application " + 
				finding.getScan().getApplication().getName());

        vulnerabilityService.updateVulnerabilityReport(
                applicationDao.retrieveById(applicationId));

		return true;
	}

    @Override
    public Scan getManualScan(Integer applicationId) {
		if (applicationId == null)
			return null;

		ApplicationChannel applicationChannel = null;
		ChannelType manualChannel = channelTypeDao
				.retrieveByName(ScannerType.MANUAL.getDisplayName());
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

		List<Finding> findingList = list();
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
				.retrieveByName(ScannerType.MANUAL.getDisplayName());
		applicationChannel.setChannelType(manualChannel);

		if (application.getChannelList() == null)
			application.setChannelList(new ArrayList<ApplicationChannel>());

		application.getChannelList().add(applicationChannel);
		applicationChannelDao.saveOrUpdate(applicationChannel);
		applicationDao.saveOrUpdate(application);
		return applicationChannel;
	}

	private String getRandomNativeId() {
		Random random = new Random();
		// get next long value
		long value = random.nextLong();

		return String.valueOf(value);
	}
}
