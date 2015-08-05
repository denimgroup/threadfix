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
package com.denimgroup.threadfix.selenium.enttests;

import com.denimgroup.threadfix.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.ScanAgentTasksPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

@Category(EnterpriseTests.class)
public class ScanAgentTaskEntIT extends BaseDataTest {

	private static final Map<String, String> scanAgentMap = new HashMap<>();
    static{
        scanAgentMap.put("ZAP", "OWASP Zed Attack Proxy");
        scanAgentMap.put("Burp", "Burp Suite Pro");
        scanAgentMap.put("Acunetix", "Acunetix WVS");
        scanAgentMap.put("AppScan", "IBM Security AppScan Standard");
    }

    @Before
    public void initialize() {
        initializeTeamAndApp();
    }

    @Test
    public void testAddScanAgentTask() {
        String scanner = scanAgentMap.get("ZAP");
        String scanTaskId;
        int scanId;

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0)
                .clickAddNewScanTask()
                .setScanQueueType(scanner)
                .submitScanQueue();

        scanTaskId = applicationDetailPage.getScanTaskId(0);

        assertTrue("Scan Queue Task is not present on the Application Detail Page.", applicationDetailPage.isScanAgentTaskPresent(scanTaskId));
        assertTrue("Scan Queue Task tab count is incorrect after adding ", 1 == applicationDetailPage.scanQueueCount());

        ScanAgentTasksPage scanAgentTasksPage = applicationDetailPage.clickScanAgentTasksLink();

        scanId = scanAgentTasksPage.getScanAgentTaskElementId(scanTaskId);

        assertTrue("Scan Agent Task is not present on the Scan Agent Task page.", scanId >= 0);
    }

    @Test
    public void testDeleteScanAgentTask() {
        String scanner = scanAgentMap.get("ZAP");
        String scanTaskId;

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0)
                .clickAddNewScanTask()
                .setScanQueueType(scanner)
                .submitScanQueue();

        scanTaskId = applicationDetailPage.getScanTaskId(0);

        assertTrue("Scan task was not created.", applicationDetailPage.isScanAgentTaskPresent(scanTaskId));

        applicationDetailPage.clickDeleteScanTaskButton("0");

        assertFalse("Scan task was not deleted.", applicationDetailPage.isScanAgentTaskPresent(scanTaskId));
    }

    //TODO evaluate
    @Test
    public void testDeleteScanFromScanAgentTaskPage() {
        String scanner = scanAgentMap.get("ZAP");
        String scanTaskId;
        int scanId;

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0)
                .clickAddNewScanTask()
                .setScanQueueType(scanner)
                .submitScanQueue();

        scanTaskId = applicationDetailPage.getScanTaskId(0);

        ScanAgentTasksPage scanAgentTasksPage = applicationDetailPage.clickScanAgentTasksLink();

        scanId = scanAgentTasksPage.getScanAgentTaskElementId(scanTaskId);

        scanAgentTasksPage.clickDeleteScan(scanId);

        assertFalse("Scan was not deleted from Scan Agent Task page.", scanAgentTasksPage.isScanAgentTaskPresent(scanTaskId));

        applicationDetailPage = scanAgentTasksPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0);

        assertFalse("Scan was not removed from the application detail page.", applicationDetailPage.isScanAgentTaskPresent(scanTaskId));
    }

	@Test
	public void testAddMultipleScans() throws MalformedURLException {
		int scanQueueCount  = 0;
        String scanTaskId;

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

		for (Entry<String, String> mapEntry : scanAgentMap.entrySet()) {
            String tempName = mapEntry.getValue();

			applicationDetailPage = applicationDetailPage.clickScanAgentTasksTab(scanQueueCount)
                    .clickAddNewScanTask()
                    .setScanQueueType(tempName)
                    .submitScanQueue();

            scanTaskId = applicationDetailPage.getScanTaskId(scanQueueCount);

			scanQueueCount++;
			assertTrue("Scan Queue Task is not present " + mapEntry.getKey(),
                    applicationDetailPage.isScanAgentTaskPresent(scanTaskId));
			assertTrue("Scan Queue Task count is incorrect after adding " + mapEntry.getKey(),
                    scanQueueCount == applicationDetailPage.scanQueueCount());
		}
		assertTrue("Scan Queue Task count is incorrect", scanQueueCount == applicationDetailPage.scanQueueCount());
	}


}
