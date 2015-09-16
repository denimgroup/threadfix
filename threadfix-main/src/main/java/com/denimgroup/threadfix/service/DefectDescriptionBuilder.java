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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.viewmodels.DefectMetadata;

import java.util.List;

/**
 * Created by mac on 11/12/14.
 */
public class DefectDescriptionBuilder {

    private DefectDescriptionBuilder(){}

    //with the template engine in place, this function is not used anymore
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

        String customCweText = null;

        if (vulnerabilities != null) {
            for (Vulnerability vulnerability : vulnerabilities) {
                if (vulnerability.getGenericVulnerability() != null &&
                        vulnerability.getSurfaceLocation() != null) {

                    if(customCweText == null){
                        customCweText = vulnerability.getGenericVulnerability().getCustomText();
                    }

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
                        
                        for(Finding finding: findings){
                    		stringBuilder.append("\n");
                        	presentFieldIfNotNull("Scanner Detail", finding.getScannerDetail(), stringBuilder);
                        	presentFieldIfNotNull("Scanner Recommendation", finding.getScannerRecommendation(), stringBuilder);
                    		presentFieldIfNotNull("Attack String", finding.getAttackString(), stringBuilder);
                        	presentFieldIfNotNull("Attack Request", finding.getAttackRequest(), stringBuilder);
                        	presentFieldIfNotNull("Attack Response", finding.getAttackResponse(), stringBuilder);
                        
                        	addDataFlow(finding, stringBuilder);
                        }
                    }

                    stringBuilder.append("\n\n");
                    vulnIndex++;
                }
            }
        }

        if(customCweText != null){
            stringBuilder.append(customCweText);
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
    
    private static void presentFieldIfNotNull(String fieldName, String fieldValue, StringBuilder builder) {
    	if (fieldValue != null && !fieldValue.isEmpty()){
    		builder
    			.append("\n")
    			.append("============================================")
    			.append("\n")
        		.append(fieldName)
        		.append("\n")
        		.append(fieldValue)
        		.append("\n");
    	}
    }
   
    private static void addDataFlow(Finding finding, StringBuilder builder) {
    	List<DataFlowElement> dataFlowElements = finding.getDataFlowElements();
    	String filename;
    	String prevFilename = null;
    	int lineNumber;
    	int prevlineNumber = -1;
    	
    	if (dataFlowElements != null && !dataFlowElements.isEmpty()) {
    		builder
    			.append("\n")
    			.append("============================================")
    			.append("\nData Flow:");
    		for(DataFlowElement dataFlowElement: dataFlowElements){
    			filename = dataFlowElement.getSourceFileName();
    			lineNumber=dataFlowElement.getLineNumber();
    			
    			if (!filename.equals(prevFilename) || lineNumber != prevlineNumber) {
    				builder
    					.append("\n")
    					.append("-----------------------------------------------------------------")
    					.append("\n")
    					.append(filename)
    					.append(" line ")
    					.append(lineNumber)
    					.append("\n")
    					.append(dataFlowElement.getLineText());
    				prevFilename = filename;
    				prevlineNumber = lineNumber;
    			}
    		}
    	}
    }

}
