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
package com.denimgroup.threadfix;


import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.ssvl.generated.ObjectFactory;
import com.denimgroup.threadfix.data.entities.ssvl.generated.Severities;
import com.denimgroup.threadfix.data.entities.ssvl.generated.Vulnerabilities;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.StringWriter;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;


/**
 * Created by stran on 7/31/15.
 */
public class ObjectToSSVLParser {

    private ObjectToSSVLParser(){}

    private static final ObjectFactory factory = new ObjectFactory();

    public static void main(String[] args){
        parse(null);
    }

    public static String parse(List<Vulnerability> tfVulnerabilities) {
        Vulnerabilities ssvlVulnerabilities = factory.createVulnerabilities();
        if (tfVulnerabilities != null)
            for (Vulnerability tfVuln: tfVulnerabilities) {
                ssvlVulnerabilities.getVulnerability().add(convertTFVulnToSSVLVuln(tfVuln));
            }

        StringWriter stringWriter = new StringWriter();
        try {
            JAXBContext context = JAXBContext.newInstance("com.denimgroup.threadfix.data.entities.ssvl.generated");
            Marshaller marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            marshaller.marshal(ssvlVulnerabilities, stringWriter);

        } catch (JAXBException e) {
            e.printStackTrace();
        }
        return stringWriter.toString();
    }

    public static List<Vulnerabilities.Vulnerability> convertTFVulnsToSSVLVulns(List<Vulnerability> tfVulnList) {
        List<Vulnerabilities.Vulnerability> ssvlVulnList = CollectionUtils.list();
        for (Vulnerability tfVuln: tfVulnList) {
            ssvlVulnList.add(convertTFVulnToSSVLVuln(tfVuln));
        }

        return ssvlVulnList;

    }

    public static Vulnerabilities.Vulnerability convertTFVulnToSSVLVuln(Vulnerability tfVuln) {
        Vulnerabilities.Vulnerability ssvlVuln = factory.createVulnerabilitiesVulnerability();
        ssvlVuln.setShortDescription(tfVuln.getGenericVulnName());
        if (tfVuln.getDefect() != null)
            ssvlVuln.setIssueID(tfVuln.getDefect().getNativeId());
        ssvlVuln.setCWE(tfVuln.getGenericVulnerability().getDisplayId());
        ssvlVuln.setSeverity(Severities.fromValue(tfVuln.getSeverityName()));
        if (tfVuln.getFindings() != null) {
            for (Finding tfFinding: tfVuln.getFindings()) {
                ssvlVuln.getFinding().add(convertTFFindingToSSVLFinding(tfFinding));
            }
        }

        return ssvlVuln;
    }

    public static List<Vulnerabilities.Vulnerability.Finding> convertTFFindingsToSSVLFindings(List<Finding> tfVulnFindings) {
        List<Vulnerabilities.Vulnerability.Finding> ssvlVulnFindings = CollectionUtils.list();
        for (Finding tfFinding: tfVulnFindings) {
            ssvlVulnFindings.add(convertTFFindingToSSVLFinding(tfFinding));
        }
        return ssvlVulnFindings;
    }

    public static Vulnerabilities.Vulnerability.Finding convertTFFindingToSSVLFinding(Finding tfFinding) {

        Vulnerabilities.Vulnerability.Finding ssvlFinding = factory.createVulnerabilitiesVulnerabilityFinding();

        ssvlFinding.setFindingDescription(tfFinding.getLongDescription());
        ssvlFinding.setNativeID(tfFinding.getNativeId());
        ssvlFinding.setSource(tfFinding.getChannelNameOrNull());
        ssvlFinding.setSourceFileName(tfFinding.getSourceFileLocation());
//        ssvlFinding.setIdentifiedTimestamp(getTimestamp(tfFinding.getScannedDate()));
        ssvlFinding.setSurfaceLocation(convertTFSurfaceLocationToSSVL(tfFinding.getSurfaceLocation()));

        if (tfFinding.getDataFlowElements() != null)
            for (DataFlowElement tfDataFlow: tfFinding.getDataFlowElements()) {
                ssvlFinding.getDataFlowElement().add(convertTFDataFlowElementToSSVL(tfDataFlow));
            }

        return ssvlFinding;
    }

    private static Vulnerabilities.Vulnerability.Finding.DataFlowElement convertTFDataFlowElementToSSVL(DataFlowElement tfDataFlowElement) {
        Vulnerabilities.Vulnerability.Finding.DataFlowElement ssvlDataFlowElement = factory.createVulnerabilitiesVulnerabilityFindingDataFlowElement();

        ssvlDataFlowElement.setLineText(tfDataFlowElement.getLineText());
        ssvlDataFlowElement.setSourceFileName(tfDataFlowElement.getSourceFileName());
        ssvlDataFlowElement.setLineNumber(BigInteger.valueOf(tfDataFlowElement.getLineNumber()));
        ssvlDataFlowElement.setColumnNumber(BigInteger.valueOf(tfDataFlowElement.getColumnNumber()));
        ssvlDataFlowElement.setSequence(BigInteger.valueOf(tfDataFlowElement.getSequence()));

        return ssvlDataFlowElement;
    }

    private static List<Vulnerabilities.Vulnerability.Finding.DataFlowElement> convertTFDataFlowElementsToSSVL(List<DataFlowElement> tfDataFlowElements) {
        if (tfDataFlowElements == null)
            return null;
        List<Vulnerabilities.Vulnerability.Finding.DataFlowElement> ssvlDataFlowElements = CollectionUtils.list();

        for (DataFlowElement tfDataFlowElement: tfDataFlowElements) {
            Vulnerabilities.Vulnerability.Finding.DataFlowElement ssvlDataFlowElement = factory.createVulnerabilitiesVulnerabilityFindingDataFlowElement();

            ssvlDataFlowElement.setLineText(tfDataFlowElement.getLineText());
            ssvlDataFlowElement.setSourceFileName(tfDataFlowElement.getSourceFileName());
            ssvlDataFlowElement.setLineNumber(BigInteger.valueOf(tfDataFlowElement.getLineNumber()));
            ssvlDataFlowElement.setColumnNumber(BigInteger.valueOf(tfDataFlowElement.getColumnNumber()));
            ssvlDataFlowElement.setSequence(BigInteger.valueOf(tfDataFlowElement.getSequence()));

            ssvlDataFlowElements.add(ssvlDataFlowElement);

        }
        return ssvlDataFlowElements;

    }

    private static Vulnerabilities.Vulnerability.Finding.SurfaceLocation convertTFSurfaceLocationToSSVL(SurfaceLocation tfSurfaceLocation) {
        if (tfSurfaceLocation == null)
            return null;

        Vulnerabilities.Vulnerability.Finding.SurfaceLocation ssvlSurfaceLocation = factory.createVulnerabilitiesVulnerabilityFindingSurfaceLocation();
        ssvlSurfaceLocation.setValue(tfSurfaceLocation.toString());
        ssvlSurfaceLocation.setSource(tfSurfaceLocation.getParameter());
        ssvlSurfaceLocation.setUrl(tfSurfaceLocation.getUrl().toString());

        return ssvlSurfaceLocation;
    }

    public static SimpleDateFormat
            OUR_DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss aaa XXX");

    public static String getTimestamp(Calendar calendar) {
        return OUR_DATE_FORMAT.format(calendar.getTime());
    }

}
