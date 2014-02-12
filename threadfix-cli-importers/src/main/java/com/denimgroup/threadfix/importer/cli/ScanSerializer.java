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

package com.denimgroup.threadfix.importer.cli;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

public class ScanSerializer {

    // Format is channel vuln code, channel vuln name, CWE, severity, file, path, parameter
    // TODO make this more configurable.
    public static String toCSVString(Scan scan) {
        StringBuilder builder = new StringBuilder();

        builder.append("Scanner Vulnerability code, Scanner Vulnerability name, " +
                "CWE Name, CWE Code, severity, file, path, parameter\n");

        for (Finding finding : scan) {
            if (finding.getChannelVulnerability() == null) {
                throw new NullPointerException("finding.getChannelVulnerability() returned null.");
            }

            if (finding.getChannelVulnerability().getGenericVulnerability() == null) {
                throw new NullPointerException("Generic Vulnerability was null for channel vulnerability with code " +
                        finding.getChannelVulnerability().getCode() + " and name " +
                        finding.getChannelVulnerability().getName());
            }

            if (finding.getChannelSeverity() == null) {
                throw new NullPointerException("Channel severity was null.");
            }

            if (finding.getChannelSeverity().getSeverityMap() == null ||
                    finding.getChannelSeverity().getSeverityMap().getGenericSeverity() == null) {
                throw new NullPointerException("Channel severity with code " + finding.getChannelSeverity().getCode()
                        + " and name " + finding.getChannelSeverity().getName()
                        + " didn't have a generic mapping.");
            }

            if (finding.getSurfaceLocation() == null) {
                throw new NullPointerException("Surface Location was null.");
            }

            builder.append(finding.getChannelVulnerability().getCode()).append(',');
            builder.append(finding.getChannelVulnerability().getName()).append(',');
            builder.append(finding.getChannelVulnerability().getGenericVulnerability().getName()).append(',');
            builder.append(finding.getChannelVulnerability().getGenericVulnerability().getId()).append(',');
            builder.append(finding.getChannelSeverity().getName()).append(',');
            builder.append(finding.getSourceFileLocation()).append(',');
            builder.append(finding.getSurfaceLocation().getPath()).append(',');
            builder.append(finding.getSurfaceLocation().getParameter());
            builder.append("\n");
        }

        return builder.toString();
    }
}
