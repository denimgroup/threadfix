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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.viewmodel.DefectMetadata;

import java.util.List;

/**
 * Created by mac on 11/12/14.
 */
public class DefectDescriptionBuilder {

    private DefectDescriptionBuilder(){}

    public static String makeDescription(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
        StringBuilder stringBuilder = new StringBuilder();

        String preamble = metadata.getPreamble();

        if (preamble != null && !"".equals(preamble)) {
            stringBuilder.append("General information\n");
            stringBuilder.append(preamble);
            stringBuilder.append('\n');
            stringBuilder.append('\n');
        }

        int vulnIndex = 0;

        if (vulnerabilities != null) {
            for (Vulnerability vulnerability : vulnerabilities) {
                if (vulnerability.getGenericVulnerability() != null &&
                        vulnerability.getSurfaceLocation() != null) {

                    stringBuilder
                            .append("Vulnerability[")
                            .append(vulnIndex)
                            .append("]:\n")
                            .append(vulnerability.getGenericVulnerability().getName())
                            .append('\n')
                            .append("CWE-ID: ")
                            .append(vulnerability.getGenericVulnerability().getId())
                            .append('\n')
                            .append("http://cwe.mitre.org/data/definitions/")
                            .append(vulnerability.getGenericVulnerability().getId())
                            .append(".html")
                            .append('\n');

                    SurfaceLocation surfaceLocation = vulnerability.getSurfaceLocation();
                    stringBuilder
                            .append("Vulnerability attack surface location:\n")
                            .append("URL: ")
                            .append(surfaceLocation.getUrl())
                            .append("\n")
                            .append("Parameter: ")
                            .append(surfaceLocation.getParameter());

                    List<Finding> findings = vulnerability.getFindings();
                    if (findings != null && !findings.isEmpty()) {
                        addUrlReferences(findings, stringBuilder);
                        addNativeIds(findings, stringBuilder);
                    }

                    stringBuilder.append("\n\n");
                    vulnIndex++;
                }
            }
        }
        return stringBuilder.toString();
    }

    private static void addUrlReferences(List<Finding> findings, StringBuilder builder) {
        builder.append("\n");

        for(Finding finding: findings){
            String channelName = finding.getChannelNameOrNull();
            if (channelName != null) {
                String urlReference = finding.getUrlReference();
                if (urlReference != null) {
                    builder.append("\n")
                            .append(channelName)
                            .append(" Vuln URL: ")
                            .append(urlReference);
                }
            }
        }
    }

    private static void addNativeIds(List<Finding> findings, StringBuilder builder) {
        for (Finding finding : findings) {
            String channelName = finding.getChannelNameOrNull();
            if (channelName != null) {
                if (ChannelType.NATIVE_ID_SCANNERS.contains(channelName)) {
                    builder.append("\n")
                            .append(channelName)
                            .append(" ID: ")
                            .append(finding.getNativeId());
                }
            }
        }
    }

}
