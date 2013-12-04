////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.selenium.pages.*;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;

import static org.junit.Assert.assertTrue;

public class ScanQueueTests extends BaseTest {

	public ScanQueueTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}

	private RemoteWebDriver driver;
	private static LoginPage loginPage;
	public ApplicationDetailPage applicationDetailPage;
	public TeamIndexPage teamIndexPage;
	private static Map<String, String> scansMap = ScanContents.SCAN_FILE_MAP;
	
	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver)super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	
	@Test
	public void testAddScanQueue() throws MalformedURLException {
		String teamName = "scanQueueTaskTeam" + getRandomString(5);
		String appName = "scanQueueTaskApp" + getRandomString(5);
		int scanQueueCnt  = 0;

		
		// log in
		teamIndexPage = loginPage.login("user", "password")
								.clickOrganizationHeaderLink()
								.clickOrganizationHeaderLink()
				 				.clickAddTeamButton()
								.setTeamName(teamName)
								.addNewTeam()
								.expandTeamRowByName(teamName)
								.addNewApplication(teamName, appName, "http://" + appName, "Low")
								.saveApplication(teamName);
		
			teamIndexPage.populateAppList(teamName);
			
			applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName);
		
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
//														.clickExpandAllVulns();

			applicationDetailPage = applicationDetailPage.clickScansQueueTab();
			scanQueueCnt++;
			assertTrue("Scan Queue Task is not present " + mapEntry.getKey(),applicationDetailPage.isScanQueuePresent(tempName));
			assertTrue("Scan Queue Task count is incorrect after adding "+mapEntry.getKey(), scanQueueCnt == applicationDetailPage.scanQueueCount());
		}
		
		assertTrue("Scan Queue Task count is incorrect", scanQueueCnt == applicationDetailPage.scanQueueCount());
		
		applicationDetailPage.clickOrganizationHeaderLink()
							.clickViewTeamLink(teamName)
							.clickDeleteButton()
							.logout();
	}

}
