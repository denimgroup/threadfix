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
package com.denimgroup.threadfix.cli;

import org.junit.Test;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;

import static org.junit.Assert.assertTrue;

/**
 * Created by mac on 5/22/14.
 */
public class VulnSearchParameterParserTests {

    private ThreadFixRestClientStub getStubWithParameters(String... parameters) {
        ThreadFixRestClientStub stub = new ThreadFixRestClientStub();

        VulnSearchParameterParser.processVulnerabilitySearchParameters(stub, parameters);

        return stub;
    }

    @Test
    public void testGenericVulnerabilityIds() {
        ThreadFixRestClientStub stub = getStubWithParameters("genericVulnerabilityIds=79,89");

        assertTrue("Missing 79.", stub.genericVulnerabilityIds.contains(79));
        assertTrue("Missing 89.", stub.genericVulnerabilityIds.contains(89));
    }

    @Test
    public void testTeamIds() {
        ThreadFixRestClientStub stub = getStubWithParameters("teamIds=1,2,3,4,5");

        for (int i = 1; i < 6; i++) {
            assertTrue("Missing " + i + ".", stub.teamIds.contains(i));
        }
    }

    @Test
    public void testApplicationIds() {
        ThreadFixRestClientStub stub = getStubWithParameters("applicationIds=1,2,3,4,5");

        for (int i = 1; i < 6; i++) {
            assertTrue("Missing " + i + ".", stub.applicationIds.contains(i));
        }
    }

    @Test
    public void testScanners() {
        ThreadFixRestClientStub stub = getStubWithParameters("scannerNames=Arachni,IBM Rational Appscan");

        assertTrue("Missing Arachni.", stub.scannerNames.contains("Arachni"));
        assertTrue("Missing IBM Rational Appscan.", stub.scannerNames.contains("IBM Rational Appscan"));
    }

    @Test
    public void testGenericSeverityValues() {
        ThreadFixRestClientStub stub = getStubWithParameters("genericSeverityValues=2,4,5");

        for (Integer i : Arrays.asList(2,4,5)) {
            assertTrue("Missing " + i + ".", stub.genericSeverityValues.contains(i));
        }
    }

    @Test
    public void testSizeLimit() {
        ThreadFixRestClientStub stub = getStubWithParameters("numberVulnerabilities=245");

        assertTrue("size value was " + stub.numberVulnerabilities + " instead of 245.", stub.numberVulnerabilities == 245);
    }

    @Test
    public void testParameter() {
        ThreadFixRestClientStub stub = getStubWithParameters("parameter=username");

        assertTrue("parameter was null.", stub.parameter != null);
        assertTrue("parameter value was " + stub.parameter + " instead of username.", stub.parameter.equals("username"));
    }

    @Test
    public void testPath() {
        ThreadFixRestClientStub stub = getStubWithParameters("path=login.jsp");

        assertTrue("path was null.", stub.path != null);
        assertTrue("path value was " + stub.path + " instead of username.", stub.path.equals("login.jsp"));
    }

    // This really only tests whether or not the parameter is going in.
    // TODO make better date-based tests
    @Test
    public void testStartDate() throws ParseException {
        Date date = new Date();

        String dateString = VulnSearchParameterParser.DATE_FORMAT.format(date);

        Date actualDate = VulnSearchParameterParser.DATE_FORMAT.parse(dateString);

        ThreadFixRestClientStub stub = getStubWithParameters("startDate=" + dateString);

        assertTrue("Date was " + stub.startDate + " instead of " + dateString +
                ".", stub.startDate.getTime() == actualDate.getTime());
    }

    // This really only tests whether or not the parameter is going in.
    // TODO make better date-based tests
    @Test
    public void testEndDate() throws ParseException {
        Date date = new Date();

        String dateString = VulnSearchParameterParser.DATE_FORMAT.format(date);

        Date actualDate = VulnSearchParameterParser.DATE_FORMAT.parse(dateString);

        ThreadFixRestClientStub stub = getStubWithParameters("endDate=" + dateString);

        assertTrue("Date was " + stub.endDate + " instead of " + dateString +
                ".", stub.endDate.getTime() == actualDate.getTime());
    }

    @Test
    public void testShowOpen() {
        ThreadFixRestClientStub stub = getStubWithParameters("showOpen=false");

        assertTrue("Should have been false.", !stub.showOpen);
    }

    @Test
    public void testShowClosed() {
        ThreadFixRestClientStub stub = getStubWithParameters("showClosed=true");

        assertTrue("Should have been true.", stub.showClosed);
    }

    @Test
    public void testShowFalsePositive() {
        ThreadFixRestClientStub stub = getStubWithParameters("showFalsePositive=true");

        assertTrue("Should have been true.", stub.showFalsePositive);
    }

    @Test
    public void testShowHidden() {
        ThreadFixRestClientStub stub = getStubWithParameters("showHidden=true");

        assertTrue("Should have been true.", stub.showHidden);
    }

    @Test
    public void testNumberMerged() {
        ThreadFixRestClientStub stub = getStubWithParameters("numberMerged=10");

        assertTrue("Should have been 10. Was " + stub.numberMerged, stub.numberMerged == 10);
    }

}
