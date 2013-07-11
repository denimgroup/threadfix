package com.denimgroup.threadfix.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;

// TODO maybe move into saveOrUpdate and call it a day
// Not sure yet though because ensureCorrectRelationships might not be what we want in all cases
public class ScanCleanerUtils extends SpringBeanAutowiringSupport {
	
	@Autowired
	private VulnerabilityDao vulnerabilityDao;
	
	private ScanCleanerUtils(){}
	
	private final SanitizedLogger log = new SanitizedLogger("ScanCleanerUtils");
	
	private static final Set<String> VULNS_WITH_PARAMETERS_SET = 
			Collections.unmodifiableSet(new HashSet<>(Arrays.asList(GenericVulnerability.VULNS_WITH_PARAMS)));
	
	public static void clean(Scan scan) {
		ScanCleanerUtils utils = new ScanCleanerUtils();
		utils.ensureCorrectRelationships(scan);
		utils.ensureSafeFieldLengths(scan);
	}
	
	/**
	 * This method ensures that Findings have the correct relationship to the
	 * other objects before being committed to the database.
	 * 
	 * It also makes sure that none of the findings have string lengths that are incompatible with their 
	 * database counterparts.
	 * 
	 * @param scan
	 */
	public void ensureCorrectRelationships(Scan scan) {
		if (scan == null) {
			log.error("The scan processing was unable to complete because the supplied scan was null.");
			return;
		}

		if (scan.getImportTime() == null)
			scan.setImportTime(Calendar.getInstance());

		if (scan.getFindings() == null) {
			log.warn("There were no findings to process.");
			return;
		}

		int numWithoutPath = 0, numWithoutParam = 0;

		// we need to set up appropriate relationships between the scan's many
		// objects.
		SurfaceLocation surfaceLocation = null;
		for (Finding finding : scan.getFindings()) {
			if (finding == null) {
				continue;
			}

			finding.setScan(scan);

			surfaceLocation = finding.getSurfaceLocation();

			if (surfaceLocation != null) {
				surfaceLocation.setFinding(finding);
				if (surfaceLocation.getParameter() == null
						&& finding.getChannelVulnerability() != null
						&& finding.getChannelVulnerability()
								.getGenericVulnerability() != null
						&& VULNS_WITH_PARAMETERS_SET.contains(finding
								.getChannelVulnerability()
								.getGenericVulnerability().getName())) {
					numWithoutParam++;
				}
				if (surfaceLocation.getPath() == null
						|| surfaceLocation.getPath().trim().equals("")) {
					numWithoutPath++;
				}
			}

			if (finding.getDataFlowElements() != null) {
				for (DataFlowElement dataFlowElement : finding
						.getDataFlowElements()) {
					if (dataFlowElement != null) {
						dataFlowElement.setFinding(finding);
					}
				}
			}

			if (finding.getVulnerability() != null) {
				if (finding.getVulnerability().getFindings() == null) {
					finding.getVulnerability().setFindings(
							new ArrayList<Finding>());
					finding.getVulnerability().getFindings().add(finding);
				}
				finding.getVulnerability().setApplication(
						finding.getScan().getApplication());
				if (finding.getVulnerability().getId() == null) {
					vulnerabilityDao.saveOrUpdate(finding.getVulnerability());
				}

				if ((finding.getVulnerability().getOpenTime() == null)
						|| (finding.getVulnerability().getOpenTime()
								.compareTo(scan.getImportTime()) > 0))
					finding.getVulnerability()
							.setOpenTime(scan.getImportTime());
			}
		}

		if (numWithoutParam > 0) {
			log.warn("There are " + numWithoutParam
					+ " injection-based findings missing parameters. "
					+ "This could indicate a bug in the ThreadFix parser.");
		}

		if (numWithoutPath > 0) {
			log.warn("There are "
					+ numWithoutPath
					+ " findings missing paths. "
					+ "This probably means there is a bug in the ThreadFix parser.");
		}
	}
	
	/**
	 * This method makes sure that the scan's findings don't have any database-incompatible field lengths
	 * 
	 * @param scan
	 */
	public void ensureSafeFieldLengths(Scan scan) {
		if (scan == null || scan.getFindings() == null
				|| scan.getFindings().size() == 0)
			return;

		for (Finding finding : scan.getFindings()) {
			if (finding == null)
				continue;

			if (finding.getLongDescription() != null
					&& finding.getLongDescription().length() > Finding.LONG_DESCRIPTION_LENGTH)
				finding.setLongDescription(finding.getLongDescription()
						.substring(0, Finding.LONG_DESCRIPTION_LENGTH - 1));
			if (finding.getNativeId() != null
					&& finding.getNativeId().length() > Finding.NATIVE_ID_LENGTH)
				finding.setNativeId(finding.getNativeId().substring(0,
						Finding.NATIVE_ID_LENGTH - 1));
			if (finding.getSourceFileLocation() != null
					&& finding.getSourceFileLocation().length() > Finding.SOURCE_FILE_LOCATION_LENGTH)
				finding.setSourceFileLocation(finding.getSourceFileLocation()
						.substring(0, Finding.SOURCE_FILE_LOCATION_LENGTH - 1));

			if (finding.getSurfaceLocation() != null) {
				SurfaceLocation location = finding.getSurfaceLocation();

				if (location.getHost() != null
						&& location.getHost().length() > SurfaceLocation.HOST_LENGTH)
					location.setHost(location.getHost().substring(0,
							SurfaceLocation.HOST_LENGTH - 1));
				if (location.getParameter() != null
						&& location.getParameter().length() > SurfaceLocation.PARAMETER_LENGTH)
					location.setParameter(location.getParameter().substring(0,
							SurfaceLocation.PARAMETER_LENGTH - 1));
				if (location.getPath() != null
						&& location.getPath().length() > SurfaceLocation.PATH_LENGTH)
					location.setPath(location.getPath().substring(0,
							SurfaceLocation.PATH_LENGTH - 1));
				if (location.getQuery() != null
						&& location.getQuery().length() > SurfaceLocation.QUERY_LENGTH)
					location.setQuery(location.getQuery().substring(0,
							SurfaceLocation.QUERY_LENGTH - 1));

				finding.setSurfaceLocation(location);
			}

			if (finding.getDataFlowElements() != null
					&& finding.getDataFlowElements().size() != 0) {
				for (DataFlowElement dataFlowElement : finding
						.getDataFlowElements()) {
					if (dataFlowElement.getLineText() != null
							&& dataFlowElement.getLineText().length() > DataFlowElement.LINE_TEXT_LENGTH)
						dataFlowElement.setLineText(dataFlowElement
								.getLineText().substring(0,
										DataFlowElement.LINE_TEXT_LENGTH - 1));
					if (dataFlowElement.getSourceFileName() != null
							&& dataFlowElement.getSourceFileName().length() > DataFlowElement.SOURCE_FILE_NAME_LENGTH)
						dataFlowElement
								.setSourceFileName(dataFlowElement
										.getSourceFileName()
										.substring(0, DataFlowElement.SOURCE_FILE_NAME_LENGTH - 1));
				}
			}
		}
	}
	
	
}
