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

    // We only want to throw errors if we're testing. Otherwise let's have defaults.
    public static boolean THROW_ERRORS = System.getProperty("SCAN_FILE_LOCATION") != null;

    // Format is channel vuln code, channel vuln name, CWE, severity, file, path, parameter
    // TODO make this more configurable.
    public static String toCSVString(Scan scan) {
        StringBuilder builder = new StringBuilder();

        builder.append("Scanner Vulnerability code, Scanner Vulnerability name, " +
                "CWE Name, CWE Code, severity, file, path, parameter, line number\n");

        for (Finding finding : scan) {
            if (THROW_ERRORS) {
                examineAndThrow(finding, builder);
            } else {
                examineAndPrintDefaults(finding, builder);
            }
        }

        return builder.toString();
    }

    private static void examineAndThrow(Finding finding, StringBuilder builder) {
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
        builder.append(finding.getSurfaceLocation().getParameter()).append(',');
        builder.append(getLineNumber(finding)).append(',');
        builder.append("\n");
    }

    private static void examineAndPrintDefaults(Finding finding, StringBuilder builder) {
        StringBuilder innerBuilder = new StringBuilder();

        if (finding.getChannelVulnerability() == null) {
            System.out.println("Got a channel vulnerability with no generic vulnerability.");
            return;
        } else {
            innerBuilder.append(finding.getChannelVulnerability().getCode()).append(',');
            innerBuilder.append(finding.getChannelVulnerability().getName()).append(',');
        }


        if (finding.getChannelVulnerability().getGenericVulnerability() == null) {
            System.out.println("Generic Vulnerability was null for channel vulnerability with code " +
                    finding.getChannelVulnerability().getCode() + " and name " +
                    finding.getChannelVulnerability().getName());

            innerBuilder.append(',').append(',');
        } else {
            innerBuilder.append(finding.getChannelVulnerability().getGenericVulnerability().getName()).append(',');
            innerBuilder.append(finding.getChannelVulnerability().getGenericVulnerability().getId()).append(',');
        }

        if (finding.getChannelSeverity() == null) {
            System.out.println("Channel severity was null.");
            innerBuilder.append(",");
        } else {
            innerBuilder.append(finding.getChannelSeverity().getName()).append(',');
        }

        if (finding.getChannelSeverity().getSeverityMap() == null ||
                finding.getChannelSeverity().getSeverityMap().getGenericSeverity() == null) {
            System.out.println("Channel severity with code " + finding.getChannelSeverity().getCode()
                    + " and name " + finding.getChannelSeverity().getName()
                    + " didn't have a generic mapping.");
        }

        innerBuilder.append(finding.getSourceFileLocation()).append(',');

        if (finding.getSurfaceLocation() == null) {
            System.out.println("Surface Location was null.");
        } else {
            innerBuilder.append(finding.getSurfaceLocation().getPath()).append(',');
            if (finding.getSurfaceLocation().getParameter() != null) {
                innerBuilder.append(finding.getSurfaceLocation().getParameter());
            }
            innerBuilder.append(',');
        }

        innerBuilder.append(getLineNumber(finding)).append(',');
        innerBuilder.append("\n");

        builder.append(innerBuilder.toString());
    }

    private static String getLineNumber(Finding finding) {
        String returnNumber = null;

        if (finding.getEntryPointLineNumber() != -1) {
            returnNumber = finding.getEntryPointLineNumber().toString();
        } else if (finding.getDataFlowElements() != null && !finding.getDataFlowElements().isEmpty()) {
            returnNumber = String.valueOf(finding.getDataFlowElements().get(0).getLineNumber());
        }

        return returnNumber;
    }
}
