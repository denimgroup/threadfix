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
package com.denimgroup.threadfix.selenium.enttests;

import com.denimgroup.threadfix.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.ScanAgentTasksPage;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

@Category(EnterpriseTests.class)
public class ScanAgentTaskEntIT extends BaseIT {

	private static final  Map<String, String> scansMap = new HashMap<>();
    static{
        scansMap.put("OWASP Zed Attack Proxy", null );
        scansMap.put("Burp Suite", null );
        scansMap.put("Acunetix WVS", null);
        scansMap.put("IBM Rational AppScan", null);
    }

    @Test
    public void testAddSingleScan() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String scanner = "OWASP Zed Attack Proxy";
        String date;
        int scanId;

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0)
                .clickAddNewScanTask()
                .setScanQueueType(scanner)
                .submitScanQueue();

        date = applicationDetailPage.getScannerDate(0);

        assertTrue("Scan Queue Task is not present on the Application Detail Page.", applicationDetailPage.isScanAgentTaskPresent(date));
        assertTrue("Scan Queue Task tab count is incorrect after adding ", 1 == applicationDetailPage.scanQueueCount());

        ScanAgentTasksPage scanAgentTasksPage = applicationDetailPage.clickScanAgentTasksLink();

        scanId = scanAgentTasksPage.getScanAgentTaskId(date);

        assertTrue("Scan Agent Task is not present on the Scan Agent Task page.", scanId >= 0);
    }

    @Test
    public void testDeleteScan() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String scanner = "OWASP Zed Attack Proxy";
        String date;

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0)
                .clickAddNewScanTask()
                .setScanQueueType(scanner)
                .submitScanQueue();

        date = applicationDetailPage.getScannerDate(0);

        assertTrue("Scan task was not created.", applicationDetailPage.isScanAgentTaskPresent(date));

        applicationDetailPage.clickDeleteScanTaskButton("0");

        assertFalse("Scan task was not deleted.", applicationDetailPage.isScanAgentTaskPresent(date));
    }

    @Test
    public void testDeleteScanFromScanAgentTaskPage() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String scanner = "OWASP Zed Attack Proxy";
        String date;
        int scanId;

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0)
                .clickAddNewScanTask()
                .setScanQueueType(scanner)
                .submitScanQueue();

        date = applicationDetailPage.getScannerDate(0);

        ScanAgentTasksPage scanAgentTasksPage = applicationDetailPage.clickScanAgentTasksLink();

        scanId = scanAgentTasksPage.getScanAgentTaskId(date);

        scanAgentTasksPage.clickDeleteScan(scanId);

        assertFalse("Scan was not deleted from Scan Agent Task page.", scanAgentTasksPage.isScanAgentTaskPresent(date));

        applicationDetailPage = scanAgentTasksPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0);

        assertFalse("Scan was not removed from the application detail page.", applicationDetailPage.isScanAgentTaskPresent(date));
    }

	@Test
	public void testAddMultipleScans() throws MalformedURLException {
		String teamName = getRandomString(8);
		String appName = getRandomString(8);
		int scanQueueCount  = 0;
        String date;

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

		for (Entry<String, String> mapEntry : scansMap.entrySet()) {
            String tempName = mapEntry.getKey();

			applicationDetailPage = applicationDetailPage.clickScanAgentTasksTab(scanQueueCount)
                    .clickAddNewScanTask()
                    .setScanQueueType(tempName)
                    .submitScanQueue();

            date = applicationDetailPage.getScannerDate(scanQueueCount);

			scanQueueCount++;
			assertTrue("Scan Queue Task is not present " + mapEntry.getKey(),
                    applicationDetailPage.isScanAgentTaskPresent(date));
			assertTrue("Scan Queue Task count is incorrect after adding " + mapEntry.getKey(),
                    scanQueueCount == applicationDetailPage.scanQueueCount());
		}
		assertTrue("Scan Queue Task count is incorrect", scanQueueCount == applicationDetailPage.scanQueueCount());
	}


}
