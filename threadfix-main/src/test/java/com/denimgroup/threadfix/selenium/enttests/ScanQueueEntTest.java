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

import static org.junit.Assert.assertTrue;

import com.denimgroup.threadfix.selenium.tests.BaseTest;
import com.denimgroup.threadfix.selenium.tests.ScanContents;
import org.junit.Test;

import java.net.MalformedURLException;
import java.util.Map;
import java.util.Map.Entry;

import com.denimgroup.threadfix.selenium.pages.*;

import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;

public class ScanQueueEntTest extends BaseTest {

	public ApplicationDetailPage applicationDetailPage;
	public TeamIndexPage teamIndexPage;

	private static Map<String, String> scansMap = ScanContents.SCAN_FILE_MAP;
	
	@Test
	public void testAddScanQueue() throws MalformedURLException {
		String teamName = "scanQueueTaskTeam" + getRandomString(3);
		String appName = "scanQueueTaskApp" + getRandomString(3);
		int scanQueueCount  = 0;

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

		teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

		applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);
		
		// create an org and an app and add scan queue task, then delete everything
		for (Entry<String, String> mapEntry : scansMap.entrySet()) {
            String tempName = mapEntry.getKey();
            if(mapEntry.getKey().equals("NTO Spider6")){
                tempName = "NTO Spider";

            }
			applicationDetailPage = applicationDetailPage.clickScansQueueTab()
                    .clickAddNewScanQueueLink()
                    .setScanQueueType(tempName)
                    .submitScanQueue();
//					.clickExpandAllVulns();

			applicationDetailPage = applicationDetailPage.clickScansQueueTab();
			scanQueueCount++;
			assertTrue("Scan Queue Task is not present " + mapEntry.getKey(),applicationDetailPage.isScanQueuePresent(tempName));
			assertTrue("Scan Queue Task count is incorrect after adding "+mapEntry.getKey(), scanQueueCount == applicationDetailPage.scanQueueCount());
		}
		assertTrue("Scan Queue Task count is incorrect", scanQueueCount == applicationDetailPage.scanQueueCount());
	}

}
