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

package com.denimgroup.threadfix.importer.utils;

import com.denimgroup.threadfix.data.entities.Finding;

import static org.junit.Assert.assertTrue;

public class SimpleFinding {

    private final String vulnType, severity, path, parameter;

    public SimpleFinding(String[] array) {
        assertTrue(array.length == 4);
        vulnType = array[0];
        severity = array[1];
        path = array[2];
        parameter = array[3] == null || array[3].equals("") ? null : array[3];
    }

    // This class assumes that every finding will have severity and vulnerability mappings.
    // This is probably a good thing.
    public boolean matches(Finding finding) {
        if (finding == null) {
            throw new IllegalArgumentException("Got a null finding. Fix the code.");
        } else if (finding.getSurfaceLocation() == null) {
            throw new IllegalArgumentException("Got a finding without a surface location.");
        }

        if (finding.getChannelSeverity() == null) {
            throw new ScannerMappingsIncompleteException("Finding must have ChannelSeverity.");
        } else if (finding.getChannelSeverity().getSeverityMap() == null) {
            throw new ScannerMappingsIncompleteException("finding.getChannelSeverity().getSeverityMap() was null.");
        } else if (finding.getChannelVulnerability() == null) {
            throw new ScannerMappingsIncompleteException("Finding must have ChannelVulnerability.");
        } else if (finding.getChannelVulnerability().getGenericVulnerability() == null) {
            throw new ScannerMappingsIncompleteException("Finding needs a mapping for ChannelVulnerability with code " +
                    finding.getChannelVulnerability().getCode() +
                    " and name " + finding.getChannelVulnerability().getName());
        }

        return matchesParameter(finding) && matchesPath(finding) &&
                finding.getChannelSeverity().getSeverityMap().getGenericSeverity().getName().equals(severity) &&
                finding.getChannelVulnerability().getGenericVulnerability().getName().equals(vulnType);
    }

    private boolean matchesParameter(Finding finding) {
        return (finding.getSurfaceLocation().getParameter() == null && parameter == null) ||
                    (finding.getSurfaceLocation().getParameter() != null &&
                finding.getSurfaceLocation().getParameter().equals(parameter));
    }

    private boolean matchesPath(Finding finding) {
        return (finding.getSurfaceLocation().getPath() == null && path == null) ||
                    (finding.getSurfaceLocation().getPath() != null &&
                        finding.getSurfaceLocation().getPath().equals(path));
    }

    @Override
    public String toString() {
        return "SimpleFinding{" +
                "vulnType='" + vulnType + '\'' +
                ", severity='" + severity + '\'' +
                ", path='" + path + '\'' +
                ", parameter='" + parameter + '\'' +
                '}';
    }
}
