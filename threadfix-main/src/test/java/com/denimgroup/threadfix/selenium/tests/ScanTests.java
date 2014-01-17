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

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;




import org.junit.*;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.ScanIndexPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.UploadScanPage;

//@RunWith (MultiThreadedRunner.class)
public class ScanTests extends BaseTest {
	
	public ScanTests(String browser) {
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
		
		return ScanTests.class.getClassLoader().getResource(string).toString();
	}
	//@Test
	public void longTeamAppNameDisplayTest(){
		String teamName = getRandomString(1024);
		String appName = getRandomString(1024);
		String rtApp = "Demo Site BE";
		String whKey = System.getProperty("WHITEHAT_KEY");
		ScanIndexPage scanIndex = loginPage.login("user", "password")
										.clickScansHeaderLink();
		int startWidth = scanIndex.getTableWidth();
		scanIndex = scanIndex.clickOrganizationHeaderLink()
 				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.expandTeamRowByIndex(teamName.substring(0, 60))
				.addNewApplication(teamName.substring(0, 60), appName, "http://" + appName.substring(0, 20), "Low")
				.saveApplication(teamName.substring(0, 60))
				.clickRemoteProvidersLink()
				.clickConfigureWhiteHat()
				.setWhiteHatAPI(whKey)
				.saveWhiteHat()
				.clickEditMapping(rtApp)
				.setTeamMapping(rtApp, teamName.substring(0, 60))
				.setAppMapping(rtApp, appName.substring(0, 60))
				.clickSaveMapping(rtApp)
				.clickImportScan(rtApp)
				.clickScansHeaderLink();
		int endWidth = scanIndex.getTableWidth();
		
		scanIndex.clickOrganizationHeaderLink().clickViewTeamLink(teamName.substring(0, 60)).clickDeleteButton();
		
		assertTrue("Scan table is too wide with max app/team length names",startWidth == endWidth);
		
		
	}
	
	// Uploads every scan type to a single app
	//needs more verfication

	@Test
	public void testUploadScans() throws MalformedURLException {
		String teamName = "uploadScan" + getRandomString(5);
		String appName = "uploadScanApp" + getRandomString(5);
		int scanCnt  = 0;
//		int vulnCnt = 0;

		// log in
		teamIndexPage = loginPage.login("user", "password")
								.clickOrganizationHeaderLink()
								.clickOrganizationHeaderLink()
				 				.clickAddTeamButton()
								.setTeamName(teamName)
								.addNewTeam()
								.expandTeamRowByIndex(teamName)
								.addNewApplication(teamName, appName, "http://" + appName, "Low")
								.saveApplication(teamName);

			teamIndexPage.populateAppList(teamName);
			
			applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName);
		
		// create an org and an app and upload the scan, then delete everything
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
			applicationDetailPage = applicationDetailPage.clickUploadScanLink()
														.setFileInput(mapEntry.getValue())
														.submitScan()
														.clickExpandAllVulns();
			//needs to be updated to take in closed vulns
			//will require being able to count vulns that get closed
//			vulnCnt += resultsMap.get(mapEntry.getKey()).length;
//			assertTrue("Unexpected vulns were added after uploading "+mapEntry.getKey(), applicationDetailPage.getVulnCount(vulnCnt));
			
			applicationDetailPage = applicationDetailPage.clickScansTab();
			scanCnt++;
			String tempName = mapEntry.getKey();
			if(mapEntry.getKey().equals("NTO Spider6")){
				tempName = "NTO Spider";
				
			}
			assertTrue("Scan Channel is not present " + mapEntry.getKey(),applicationDetailPage.isScanChannelPresent(tempName));
			assertTrue("Scan count is incorrect after uploading "+mapEntry.getKey(), scanCnt == applicationDetailPage.scanCount());
			applicationDetailPage = applicationDetailPage.clickVulnTab();
		}
		
		assertTrue("Scan count is incorrect", scanCnt == applicationDetailPage.scanCount());
		
		applicationDetailPage.clickOrganizationHeaderLink()
							.clickViewTeamLink(teamName)
							.clickDeleteButton()
							.logout();
	}

   // @Ignore
	@Test
	public void microsoftCatNetScan() {
		String key = "Microsoft CAT.NET";
		String[][] expectedResults = resultsMap.get(key);
		

		
		runScanTest(key, expectedResults);
	}

//    @Ignore
	@Test
	public void findBugsScan() {
		
		String key = "FindBugs";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);
	}

//    @Ignore
	@Test
	public void ibmAppscanScan() {
		String key = "IBM Rational AppScan";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);
	}

//    @Ignore
	@Test
	public void netsparkerScan(){
		String key = "Mavituna Security Netsparker";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);
	}

 //   @Ignore
	@Test
	public void skipFishScan(){
		String key = "Skipfish";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);
	}

//    @Ignore
	@Test
	public void ntoSpiderScan() {
		String key = "NTO Spider";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);
	}

//    @Ignore
	@Test
	public void ntoSpiderScan6() {
		
		String key = "NTO Spider6";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);
	}
	
//    @Ignore
	@Test
	public void w3afScan() {
		
		String key = "w3af";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);		
	}

//    @Ignore
	@Test
	public void zaproxyScan() {
		String key = "OWASP Zed Attack Proxy";
		String[][] expectedResults = resultsMap.get(key);

		runScanTest(key, expectedResults);
	}

//    @Ignore
	@Test
	public void nessusScan() {
		String key = "Nessus";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);		
	}

//    @Ignore
	@Test
	public void arachniScan() {
		String key = "Arachni";
		String[][] expectedResults = resultsMap.get(key);

		runScanTest(key, expectedResults);		
	}

//    @Ignore
	@Test
	public void webInspectScan() {
		String key = "WebInspect";
		String[][] expectedResults = resultsMap.get(key);

		runScanTest(key,expectedResults);
	}

//    @Ignore
	@Test
	public void brakeManScan() {
		String key = "Brakeman";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);		

	}

//    @Ignore
	@Test
	public void fortify360Scan() {
		String key = "Fortify 360";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);
	}

//    @Ignore
	@Test
	public void acunetixScan() {
		String key = "Acunetix WVS";
		String[][] expectedResults = resultsMap.get(key);

		
		runScanTest(key, expectedResults);
	}

//    @Ignore
	@Test
	public void burpScan() {
		String key = "Burp Suite";
		String[][] expectedResults = resultsMap.get(key);


		runScanTest(key, expectedResults);
	}

	public void runScanTest(String scannerName, String[][] expectedResults) {
		teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();
		
		String orgName = scannerName + getRandomString(10);
		String appName = scannerName + getRandomString(10);

		applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
													 .clickAddTeamButton()
													 .setTeamName(orgName)
													 .addNewTeam()
													 .addNewApplication(orgName, appName, "http://" + scannerName, "Low")
													 .saveApplication(orgName)
													 .clickViewAppLink(appName, orgName)
													 .clickUploadScanLink()
													 .setFileInput(fileMap.get(scannerName))
													 .submitScan()
													 .clickExpandAllVulns();
		
		assertTrue("The vuln counts don't match.", applicationDetailPage.getVulnCount(expectedResults.length));
		
		String[][] tableResults = new String[expectedResults.length][4];
		for (int i=1; i <= expectedResults.length; i++) {
			String[] thisVuln = new String[] {
					applicationDetailPage.getElementText("type" + i),
					applicationDetailPage.getElementText("severity" + i),
					applicationDetailPage.getElementText("path" + i),
					applicationDetailPage.getElementText("parameter" + i)
				};
			tableResults[i-1] = thisVuln;
		}


        outer: for (int i=0; i <= expectedResults.length - 1; i++) {
			for (int j=0; j <= expectedResults.length-1; j++) {
				if (expectedResults[i][0].equals(tableResults[j][0]) &&
						expectedResults[i][1].equals(tableResults[j][1]) &&
						expectedResults[i][2].equals(tableResults[j][2]) &&
						expectedResults[i][3].equals(tableResults[j][3])) {
					continue outer;
				}
			}
            sleep(10000);
			assertTrue("Didn't find a vuln: " + expectedResults[i][0] 
					+ ", " + expectedResults[i][1]
					+ ", " + expectedResults[i][2]
					+ ", " + expectedResults[i][3], 
					false);
		}
		String tempName = scannerName;
		if(scannerName.equals("NTO Spider6")){
			tempName = "NTO Spider";
			
		}
		applicationDetailPage = applicationDetailPage.clickScansTab();
		assertTrue("Scan Count is incorrect.", applicationDetailPage.isScanCountCorrect(1));	
		assertTrue("Scan Tab is incorrect.", applicationDetailPage.isScanPresent(tempName));
		
		int scanCount = applicationDetailPage.scanCount();
		//duplicate scan checking
		applicationDetailPage = applicationDetailPage.clickUploadScanLink()
		 											.setFileInput(fileMap.get(scannerName))
		 											.submitScanInvalid();
		
		assertTrue("Duplicate error not displayed",applicationDetailPage.isDuplicateScan());
		
		applicationDetailPage.clickCloseScanUploadModal()
							.clickVulnTab()
							.clickExpandAllVulns();
		
		assertTrue("Scan count is incorrect", scanCount == applicationDetailPage.scanCount());
		
		for (int i=1; i <= expectedResults.length; i++) {
			String[] thisVuln = new String[] {
					applicationDetailPage.getElementText("type" + i),
					applicationDetailPage.getElementText("severity" + i),
					applicationDetailPage.getElementText("path" + i),
					applicationDetailPage.getElementText("parameter" + i)
				};
			tableResults[i-1] = thisVuln;
		}
		
		outer: for (int i=0; i <= expectedResults.length - 1; i++) {
			for (int j=0; j <= expectedResults.length-1; j++) {
				if (expectedResults[i][0].equals(tableResults[j][0]) &&
						expectedResults[i][1].equals(tableResults[j][1]) &&
						expectedResults[i][2].equals(tableResults[j][2]) &&
						expectedResults[i][3].equals(tableResults[j][3])) {
					continue outer;
				}
			}
            sleep(5000);
			assertTrue("Didn't find a vuln after duplicate scan upload: " + expectedResults[i][0] 
					+ ", " + expectedResults[i][1]
					+ ", " + expectedResults[i][2]
					+ ", " + expectedResults[i][3], 
					false);
		}
		
		assertTrue("Unexpected vulns were added", applicationDetailPage.getVulnCount(expectedResults.length));
		
		
		applicationDetailPage.clickOrganizationHeaderLink()
							.clickViewTeamLink(orgName)
							.clickDeleteButton();
	}
}
