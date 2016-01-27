////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.defects.utils.tfs;

import com.denimgroup.threadfix.viewmodels.DefectMetadata;
import com.denimgroup.threadfix.viewmodels.DynamicFormField;

import java.util.List;
import java.util.Map;

/**
 * Created by mac on 4/8/14.
 */
public interface TFSClient {

    // Passing two maps and using mutable state is gross but we don't have to define an object
    void updateDefectIdMaps(String ids, Map<String, String> stringStatusMap, Map<String, Boolean> openStatusMap);

    List<String> getDefectIds(String projectName);

    List<DynamicFormField> getDynamicFormFields(String projectName);

    enum ConnectionStatus {
        VALID, INVALID, INVALID_CERTIFICATE
    }

    List<String> getProjectNames();

    String getProjectId(String projectName);

    ConnectionStatus configure(String url, String user, String password);

    ConnectionStatus checkUrl(String url);

    String createDefect(String projectName, DefectMetadata metadata, String description);

}
