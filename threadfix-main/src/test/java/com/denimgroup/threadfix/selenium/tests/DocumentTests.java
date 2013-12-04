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

//@RunWith (MultiThreadedRunner.class)
public class DocumentTests extends BaseTest {

	public DocumentTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}


	private RemoteWebDriver driver;
	private static LoginPage loginPage;
	public ApplicationDetailPage applicationDetailPage;
	public UploadScanPage uploadScanPage;
	public TeamIndexPage teamIndexPage;
	public TeamDetailPage teamDetailPage;
	
	public String appWasAlreadyUploadedErrorText = "Scan file has already been uploaded.";
		
	private static Map<String, String[][]> resultsMap = ScanContents.SCAN_RESULT_MAP;
	private static Map<String, String> fileMap = ScanContents.SCAN_FILE_MAP;
	
	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver)super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	
	public static String getScanFilePath(String category, String scannerName, String fileName) {
		String string = "SupportingFiles/" + category  + "/" + scannerName + "/" + fileName;
		
		String urlFromCommandLine = System.getProperty("scanFileBaseLocation");
		if (urlFromCommandLine != null) {
			return urlFromCommandLine + string;
		}
		
		return DocumentTests.class.getClassLoader().getResource(string).toString();
	}
	
	// Uploads every scan type to a single app
	//needs more verfication
	@Test
	public void testUploadScans() throws MalformedURLException {
		String teamName = "uploadDocTeam" + getRandomString(5);
		String appName = "uploadDocApp" + getRandomString(5);
		int docCnt  = 0;

		
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
		
		// create an org and an app and upload the documents, then delete everything
		for (Entry<String, String> mapEntry : fileMap.entrySet()) {
			if (mapEntry.getValue() != null){
				File appScanFile = null;
				
				if (System.getProperty("scanFileBaseLocation") == null) {
					appScanFile = new File(new URL(mapEntry.getValue()).getFile());
				} else {
					appScanFile = new File(mapEntry.getValue());
				}
				assertTrue("The test file did not exist.", appScanFile.exists());
			} else {
				continue;
			}
			applicationDetailPage = applicationDetailPage.clickDocumentTab()
														.setDocFileInput(mapEntry.getValue())
														.submitDoc();

			applicationDetailPage = applicationDetailPage.clickDocumentTab();
			docCnt++;

//			String tempName = mapEntry.getKey();
//			assertTrue("Scan Channel is not present " + mapEntry.getKey(),applicationDetailPage.isScanChannelPresent(tempName));
//			assertTrue("Scan count is incorrect after uploading "+mapEntry.getKey(), docCnt == applicationDetailPage.scanCount());
		}
		
		assertTrue("Document count is incorrect", docCnt == applicationDetailPage.docsCount());
		
		applicationDetailPage.clickOrganizationHeaderLink()
							.clickViewTeamLink(teamName)
							.clickDeleteButton()
							.logout();
	}
}
