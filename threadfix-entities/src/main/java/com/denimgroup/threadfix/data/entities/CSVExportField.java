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

package com.denimgroup.threadfix.data.entities;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * @author zabdisubhan
 */
public enum CSVExportField {
    UNIQUE_ID("Unique ID"),
    CWE_ID("CWE ID"),
    CWE_NAME("CWE Name"),
    PATH("Path"),
    PARAMETER("Parameter"),
    SEVERITY("Severity"),
    OPEN_DATE("Open Date"),
    DESCRIPTION("Description"),
    DEFECT_ID("Defect ID"),
    APPLICATION_NAME("Application Name"),
    TEAM_NAME("Team Name"),
    PAYLOAD("Payload"),
    ATTACK_SURFACE_PATH("Attack Surface Path"),
    ATTACK_STRING("Attack String"),
    ATTACK_REQUEST("Attack Request"),
    ATTACK_RESPONSE("Attack Response"),
    SCANNER_DETAIL("Scanner Detail"),
    SCANNER_RECOMMENDATION("Scanner Recommendation");

    private String displayName;

    public String getDisplayName() {
        return this.displayName;
    }

    private CSVExportField(String displayName) {
        this.displayName = displayName;
    }

    public static Map<String, String> getExportFields() {

        Map<String, String> exportFieldDisplayNames = map();
        CSVExportField[] enumFields = CSVExportField.values();

        for (CSVExportField enumField : enumFields) {
            exportFieldDisplayNames.put(enumField.toString(), enumField.getDisplayName());
        }

        return exportFieldDisplayNames;
    }
}
