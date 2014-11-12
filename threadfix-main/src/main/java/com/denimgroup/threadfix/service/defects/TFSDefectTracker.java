////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.defects.utils.tfs.TFSClient;
import com.denimgroup.threadfix.service.defects.utils.tfs.TFSClientImpl;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class TFSDefectTracker extends AbstractDefectTracker {

	public TFSDefectTracker() {}

    static {
        System.setProperty("com.microsoft.tfs.client.allowInsecureBasic", "true");
    }

    TFSClient client = new TFSClientImpl();

    private boolean configureClient() {
        assert getUrl() != null;
        assert getUsername() != null;
        assert getPassword() != null;

        TFSClient.ConnectionStatus status = client.configure(getUrl(), getUsername(), getPassword());

        if (status == TFSClient.ConnectionStatus.INVALID_CERTIFICATE) {
            log.error("Invalid Certificate encountered. The certificate needs to be added to the keystore in order to continue.");
        }

        return status == TFSClient.ConnectionStatus.VALID;
    }


	@Override
	public String createDefect(List<Vulnerability> vulnerabilities,
			DefectMetadata metadata) {

        assert vulnerabilities != null && vulnerabilities.size() > 0;
        assert metadata != null;

		boolean validConfiguration = configureClient();
		
		if (validConfiguration) {
            return client.createDefect(getProjectName(), metadata, makeDescription(vulnerabilities, metadata));
		} else {
            log.warn("Unable to create defect.");
            return null;
        }
	}

	@Override
	public String getBugURL(String endpointURL, String bugID) {
		return null;
	}

	@Override
	public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {

        boolean validConfiguration = configureClient();

        if (validConfiguration) {

            Map<Defect, Boolean> returnMap = new HashMap<>();
            Map<String, String> stringStatusMap = new HashMap<>();
            Map<String, Boolean> openStatusMap = new HashMap<>();

            StringBuilder builder = new StringBuilder();

            for (Defect defect : defectList) {
                builder.append(defect.getNativeId()).append(",");
            }

            String ids = builder.substring(0, builder.length() - 1);

            log.info("Updating bug statuses.");

            client.updateDefectIdMaps(ids, stringStatusMap, openStatusMap);

            // Find the open or closed status for each defect.
            for (Defect defect : defectList) {
                if (defect != null) {
                    returnMap.put(defect, openStatusMap.get(defect.getNativeId()));
                    defect.setStatus(stringStatusMap.get(defect.getNativeId()));
                }
            }

		    return returnMap;

        } else {
			log.warn("Updating bug status failed.");
			return null;
		}
    }

	@Nonnull
    @Override
	public List<String> getProductNames() {
		log.info("Getting list of product names.");
        boolean validConfiguration = configureClient();

        if (validConfiguration) {
            List<String> productNames = client.getProjectNames();

            if (productNames == null || productNames.size() == 0) {
                log.warn("Collection of projects was null or empty.");
                return list();
            }

            return productNames;
        } else {
			log.warn("Unable to retrieve WorkItemClient, returning an unauthorized message.");
			setLastError("Invalid username / password combination");
			return list();
		}
	}

	@Override
	public String getProjectIdByName() {
        assert getProjectName() != null;

        boolean validConfiguration = configureClient();

        if (validConfiguration) {
            return client.getProjectId(getProjectName());
        } else {
			log.warn("Unable to connect to TFS to retrieve project name.");
			return null;
		}
	}

	@Override
	public ProjectMetadata getProjectMetadata() {
		log.info("Collecting project metadata");

        boolean validConfiguration = configureClient();

        if (validConfiguration) {
            List<String> statuses = new ArrayList<>();
            List<String> priorities = client.getPriorities();
            List<String> emptyList = new ArrayList<>();
            emptyList.add("-");

            statuses.add("New");

            log.info("End Collecting project metadata " + priorities);

            return new ProjectMetadata(emptyList, emptyList, emptyList, statuses,
                    priorities);
        } else {
            log.error("Invalid configuration.");
            return null;
        }
	}

	@Override
	public String getTrackerError() {
		log.info("Returning the error from the tracker.");
		return "The tracker failed to export a defect.";
	}

	@Override
	public boolean hasValidCredentials() {
		return configureClient();
	}

	@Override
	public boolean hasValidProjectName() {

        assert getProjectName() != null : "The project name should always be set before this method is called.";

        if (getProjectName() == null) {
			return false;
		}

        boolean validConfiguration = configureClient();

        if (validConfiguration) {
            return client.getProjectNames().contains(getProjectName());

        } else {
			log.warn("Unable to connect to TFS, unable to determine whether the project name was valid.");
			return false;
		}
	}

	@Override
	public boolean hasValidUrl() {
        assert getUrl() != null : "This will cause a NPE.";

        TFSClient.ConnectionStatus status = client.checkUrl(getUrl());

        if (status == TFSClient.ConnectionStatus.INVALID_CERTIFICATE) {
            setLastError(AbstractDefectTracker.INVALID_CERTIFICATE);
        }

        return status == TFSClient.ConnectionStatus.VALID;
	}
	
	@Override
	public List<Defect> getDefectList() {

        assert getProjectName() != null;

        boolean validConfiguration = configureClient();

        if (validConfiguration) {
            getProjectName();

            List<String> defectIds = client.getDefectIds(getProjectName());

            List<Defect> defects = new ArrayList<>();

            for (String id : defectIds) {
                Defect defect = new Defect();
                defect.setNativeId(id);
                defects.add(defect);
            }

            return defects;
        } else {
            return null;
        }
	}
}
