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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class DocumentIT extends BaseIT {

	private static Map<String, String> fileMap = ScanContents.SCAN_FILE_MAP;
	
	@Test
	public void testUploadScans() throws MalformedURLException {
		String teamName = createTeam();
		String appName = createApplication(teamName);
        File appScanFile;
        int docCnt  = 0;

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);
		
		for (Entry<String, String> mapEntry : fileMap.entrySet()) {
			if (mapEntry.getValue() != null){
				if (System.getProperty("scanFileBaseLocation") == null) {
					appScanFile = new File(new URL(mapEntry.getValue()).getFile());
				} else {
					appScanFile = new File(mapEntry.getValue());
				}
				assertTrue("The test file did not exist.", appScanFile.exists());
			} else {
				continue;
			}
			applicationDetailPage = applicationDetailPage.clickDocumentTab(docCnt)
                    .clickUploadDocLink()
                    .setDocFileInput(mapEntry.getValue());

			docCnt++;
		}
		assertTrue("Document count is incorrect", docCnt == applicationDetailPage.docsCount());
	}

	@Test
	public void testUploadEmptyScan() {
		String teamName = createTeam();
		String appName = createApplication(teamName);

		loginPage.defaultLogin()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName).clickActionButton()
				.clickUploadScan()
				.uploadEmptyScan(ScanContents.getScanFilePath("Empty Scan"));

		assertTrue("Scan was not uploaded", driver.findElement(By.linkText("1 Scan")).isDisplayed());
	}
}
