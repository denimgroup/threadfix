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
package com.denimgroup.threadfix.service.merge;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.VulnerabilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

// TODO maybe move into saveOrUpdate and call it a day
// Not sure yet though because ensureCorrectRelationships might not be what we want in all cases
@Component
public class ScanCleanerUtils {
	
	@Autowired
	private VulnerabilityService vulnerabilityService;
	
    private static final SanitizedLogger log = new SanitizedLogger("ScanCleanerUtils");

    private static final Set<String> VULNS_WITH_PARAMETERS_SET =
            Collections.unmodifiableSet(set(GenericVulnerability.VULNS_WITH_PARAMS));

    public void clean(Scan scan) {
        assert vulnerabilityService != null : "vulnerabilityService was null. Fix your Spring configuration.";
        ensureCorrectRelationships(scan);
        ensureSafeFieldLengths(scan);
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
					finding.getVulnerability().setFindings(new ArrayList<Finding>());
					finding.getVulnerability().getFindings().add(finding);
				}
				finding.getVulnerability().setApplication(
                        finding.getScan().getApplication());

				if (finding.getVulnerability().getId() == null) {
					vulnerabilityService.storeVulnerability(finding.getVulnerability(), EventAction.VULNERABILITY_CREATE);
				}
                finding.getScan().getApplication().addVulnerability(finding.getVulnerability());

				if (finding.getScannedDate() != null) {
					if (finding.getScannedDate().before(finding.getVulnerability().getOpenTime())) {
						finding.getVulnerability().setOpenTime(finding.getScannedDate());
					}
				} else if ((finding.getVulnerability().getOpenTime() == null)
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

			finding.setLongDescription(trim(finding.getLongDescription(), Finding.LONG_DESCRIPTION_LENGTH));
			finding.setNativeId(trim(finding.getNativeId(), Finding.NATIVE_ID_LENGTH));
			finding.setSourceFileLocation(trim(finding.getSourceFileLocation(), Finding.SOURCE_FILE_LOCATION_LENGTH));
			finding.setAttackResponse(trim(finding.getAttackResponse(), Finding.ATTACK_RESPONSE_LENGTH));
			finding.setAttackRequest(trim(finding.getAttackRequest(), Finding.ATTACK_REQUEST_LENGTH));


			if (finding.getSurfaceLocation() != null) {
				SurfaceLocation location = finding.getSurfaceLocation();
				
				location.setHost(trim(location.getHost(), SurfaceLocation.HOST_LENGTH));
				location.setParameter(trim(location.getParameter(), SurfaceLocation.PARAMETER_LENGTH));
				location.setPath(trim(location.getPath(), SurfaceLocation.PATH_LENGTH));
				location.setQuery(trim(location.getQuery(), SurfaceLocation.QUERY_LENGTH));

				finding.setSurfaceLocation(location);
			}

			if (finding.getDataFlowElements() != null
					&& finding.getDataFlowElements().size() != 0) {
				for (DataFlowElement dataFlowElement : finding.getDataFlowElements()) {
					dataFlowElement.setLineText(
							trim(dataFlowElement.getLineText(), DataFlowElement.LINE_TEXT_LENGTH));
					dataFlowElement.setSourceFileName(
							trim(dataFlowElement.getSourceFileName(), DataFlowElement.SOURCE_FILE_NAME_LENGTH));
				}
			}
		}
	}
	
	private static String trim(String inputString, int length) {
		String returnString = inputString;
		
		if (returnString != null && returnString.length() > length) {
			returnString = returnString.substring(0, length - 1);
		}
		
		return returnString;
	}
}
