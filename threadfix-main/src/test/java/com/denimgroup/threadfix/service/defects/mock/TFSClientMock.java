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
package com.denimgroup.threadfix.service.defects.mock;

import com.denimgroup.threadfix.service.defects.utils.tfs.TFSClient;
import com.denimgroup.threadfix.viewmodel.DefectMetadata;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.service.defects.util.TestConstants.*;

public class TFSClientMock implements TFSClient {
    ConnectionStatus status = ConnectionStatus.INVALID;

    public static final List<String> projectNames = Arrays.asList(TFS_PROJECT, "Project A", "Project B", "Project C",
            "Project D");
    public static final List<String> priorities = Arrays.asList("Priority 1");
    public static final List<String> defects = Arrays.asList("Defect 1", "Defect 2", "Defect 3");

    @Override
    public void updateDefectIdMaps(String ids, Map<String, String> stringStatusMap, Map<String, Boolean> openStatusMap) {

    }

    @Override
    public List<String> getPriorities() {
        return priorities;
    }

    @Override
    public List<String> getDefectIds(String projectName) {
        return defects;
    }

    @Override
    public List<String> getProjectNames() {
        return projectNames;
    }

    @Override
    public String getProjectId(String projectName) {
        return null;
    }

    @Override
    public ConnectionStatus configure(String url, String user, String password) {
        if(url.equals(TFS_BASE_URL) && user.equals(TFS_USERNAME) && password.equals(TFS_PASSWORD)) {
            status = ConnectionStatus.VALID;
            return ConnectionStatus.VALID;
        }
        return status = ConnectionStatus.INVALID;
    }

    @Override
    public ConnectionStatus checkUrl(String url) {
        if (TFS_BASE_URL.equals(url)) {
            return ConnectionStatus.VALID;
        }
        return ConnectionStatus.INVALID;
    }

    @Override
    public String createDefect(String projectName, DefectMetadata metadata, String description) {
        return null;
    }
}
