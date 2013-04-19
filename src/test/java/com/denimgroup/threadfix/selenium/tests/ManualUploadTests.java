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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.firefox.FirefoxDriver;

import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.FindingEditPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.ManualUploadPage;

public class ManualUploadTests extends BaseTest {
	private FirefoxDriver driver;
	private ManualUploadPage manualUploadPage;
	private ApplicationDetailPage applicationDetailPage;
	private LoginPage loginPage;
	private FindingEditPage editPage;

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}

	@After
	public void shutDown() {
		driver.quit();
	}

	/*
	@Test
	public void testNavigation() {
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", manualUploadPage.getH2Tag().contains("New Finding"));
		
		manualUploadPage.clickBack().clickDeleteLink().clickDeleteButton().logout();
	}
	*/

	/*
	@Test
	public void testAllSeveritiesDynamic() {
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", manualUploadPage.getH2Tag().contains("New Finding"));
		
		applicationDetailPage = manualUploadPage
				.fillAllClickSaveDynamic(
						true,
						"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						"/demo/EvalInjection2.php",
						"command",
						"Critical",
						"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')");
		
		for (String severity : new String[] {"Critical", "High", "Medium", "Low", "Info" }) {
			editPage = applicationDetailPage.clickVulnLink(1)
					.clickEditLink()
					.selectSeverityList(severity)
					.clickDynamicSubmit()
					.clickVulnLink(1)
					.clickEditLink();
			assertTrue("The severity didn't persist correctly.", severity.equals(editPage.getSeverity()));
			applicationDetailPage = editPage.clickDynamicSubmit();
		}
		
		applicationDetailPage.clickDeleteLink().clickDeleteButton().logout();
	}
	*/
	/*
	@Test
	public void testAllSeveritiesStatic() {
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", manualUploadPage.getH2Tag().contains("New Finding"));
		
		applicationDetailPage = manualUploadPage
				.fillAllClickSaveStatic(
						true,
						"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						"/demo/EvalInjection2.php",
						"1",
						"command",
						"Critical",
						"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')");
		
		for (String severity : new String[] {"Critical", "High", "Medium", "Low", "Info" }) {
			editPage = applicationDetailPage.clickVulnLink(1)
					.clickEditLink()
					.selectSeverityList(severity)
					.clickStaticSubmit()
					.clickVulnLink(1)
					.clickEditLink();
			assertTrue("The severity didn't persist correctly.", severity.equals(editPage.getSeverity()));
			applicationDetailPage = editPage.clickStaticSubmit();
		}
		
		applicationDetailPage.clickDeleteLink().clickDeleteButton().logout();
	}
	*/
	/*
	@Test
	public void dynamicValidationTest(){
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", manualUploadPage.getH2Tag().contains("New Finding"));
		
		manualUploadPage = manualUploadPage.clickDynamicSubmitInvalid();

		String ErrorText = driver.findElementById("channelVulnerability.code.errors").getText();
		assertTrue("Error message not displayed", ErrorText.equals("Vulnerability is a required field."));
		
		String DescError = driver.findElementById("longDescription.errors").getText();
		assertTrue("Description Error not Found", DescError.equals("Description is a required field."));
		
		manualUploadPage.clickBack();
		applicationDetailPage = new ApplicationDetailPage(driver);
		applicationDetailPage.clickDeleteLink().clickDeleteButton().logout();
	}
	*/
	/*
	@Test
	public void staticValidationTest(){
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", manualUploadPage.getH2Tag().contains("New Finding"));
				
		manualUploadPage = manualUploadPage.setStaticRadioButton(true).clickStaticSubmitInvalid();
		
		String errorText = driver.findElementById("channelVulnerability.code.errors").getText();
		assertTrue("Error message not displayed", errorText.equals("Vulnerability is a required field."));
	
		String descError = driver.findElementById("longDescription.errors").getText();
		assertTrue("Description Error not Found", descError.equals("Description is a required field."));
		
		manualUploadPage.clickBack().clickDeleteLink().clickDeleteButton().logout();
	}
	*/
	/*
	@Test
	public void dynamicInvalidVulnsTest(){
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", manualUploadPage.getH2Tag().contains("New Finding"));
		
		manualUploadPage.fillAllClickSaveStatic(true, "ABCDEFGHIJKL",
				"/demo/PredictableResource.php", "123", " ", "Info","Improper Cross-boundary Removal of Sensitive Data");	
		
		manualUploadPage = new ManualUploadPage(driver);
		String ErrorText = driver.findElementById("channelVulnerability.code.errors").getText();
		assertTrue("Error message not displayed", ErrorText.equals("Vulnerability is invalid."));
		
		manualUploadPage.clickBack().clickDeleteLink().clickDeleteButton().logout();
	}
	*/
	
	///////////////////////////////////////////
	// EDIT ///////////////////////////////////
	///////////////////////////////////////////
	/*
	@Test
	public void testEditDynamic() {
		String cwe1 = GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, 
				cwe2 = GenericVulnerability.CWE_BLIND_XPATH_INJECTION,
				path1 = "/normal/first/path.jsp",
				path2 = "/normal/second/path.jsp",
				param1 = "parameter 1",
				param2 = "parameter 2",
				severity1 = "Critical",
				severity2 = "High",
				description1 = "description 1",
				description2 = "description 2";
		
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", manualUploadPage.getH2Tag().contains("New Finding"));
		
		applicationDetailPage = manualUploadPage.fillAllClickSaveDynamic(true, cwe1, path1, param1, severity1, description1);	
		
		FindingEditPage editPage = applicationDetailPage.clickVulnLink(1).clickEditLink();
		
		assertTrue("Parameter didn't make it.", param1.equals(editPage.getParameter()));
		assertTrue("URL didn't make it.", path1.equals(editPage.getURL()));
		assertTrue("Severity didn't make it.", severity1.equals(editPage.getSeverity()));
		assertTrue("CWE didn't make it.", cwe1.equals(editPage.getCWE()));
		assertTrue("Description didn't make it.", description1.equals(editPage.getDescription()));
		
		editPage = editPage.fillAllClickSaveDynamic(true, cwe2, path2, param2, severity2, description2)
				.clickVulnLink(1).clickEditLink();
		
		assertTrue("Parameter didn't make it the second time.", param2.equals(editPage.getParameter()));
		assertTrue("URL didn't make it the second time.", path2.equals(editPage.getURL()));
		assertTrue("Severity didn't make it the second time.", severity2.equals(editPage.getSeverity()));
		assertTrue("CWE didn't make it the second time.", cwe2.equals(editPage.getCWE()));
		assertTrue("Description didn't make it the second time.", description2.equals(editPage.getDescription()));
		
		applicationDetailPage = editPage.clickDynamicSubmit();
		
		applicationDetailPage.clickDeleteLink().clickDeleteButton().logout();
	}
	*/
	/*
	@Test
	public void testEditStatic() {
		String cwe1 = GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, 
				cwe2 = GenericVulnerability.CWE_BLIND_XPATH_INJECTION,
				path1 = "/normal/first/path.jsp",
				path2 = "/normal/second/path.jsp",
				param1 = "parameter 1",
				param2 = "parameter 2",
				severity1 = "Critical",
				severity2 = "High",
				description1 = "description 1",
				description2 = "description 2",
				line1 = "1",
				line2 = "2";
		
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", manualUploadPage.getH2Tag().contains("New Finding"));
		
		applicationDetailPage = manualUploadPage.fillAllClickSaveStatic(true, cwe1, path1, line1, param1, severity1, description1);	
		
		FindingEditPage editPage = applicationDetailPage.clickVulnLink(1).clickEditLink();
		
		assertTrue("Parameter didn't make it.", param1.equals(editPage.getParameter()));
		assertTrue("URL didn't make it.", path1.equals(editPage.getSourceFile()));
		assertTrue("Line # didn't make it.", line1.equals(editPage.getLineNumber()));
		assertTrue("Severity didn't make it.", severity1.equals(editPage.getSeverity()));
		assertTrue("CWE didn't make it.", cwe1.equals(editPage.getCWE()));
		assertTrue("Description didn't make it.", description1.equals(editPage.getDescription()));
		
		editPage = editPage.fillAllClickSaveStatic(true, cwe2, path2, line2, param2, severity2, description2)
				.clickVulnLink(1).clickEditLink();
		
		assertTrue("Parameter didn't make it the second time.", param2.equals(editPage.getParameter()));
		assertTrue("URL didn't make it the second time.", path2.equals(editPage.getSourceFile()));
		assertTrue("Line # didn't make it.", line2.equals(editPage.getLineNumber()));
		assertTrue("Severity didn't make it the second time.", severity2.equals(editPage.getSeverity()));
		assertTrue("CWE didn't make it the second time.", cwe2.equals(editPage.getCWE()));
		assertTrue("Description didn't make it the second time.", description2.equals(editPage.getDescription()));
		
		applicationDetailPage = editPage.clickStaticSubmit();
		
		applicationDetailPage.clickDeleteLink().clickDeleteButton().logout();
	}
	*/
	/*
	@Test
	public void testEditSwitchStaticDynamic() {
		String cwe1 = GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, 
				cwe2 = GenericVulnerability.CWE_BLIND_XPATH_INJECTION,
				path1 = "/normal/first/path.jsp",
				path2 = "/normal/second/path.jsp",
				param1 = "parameter 1",
				param2 = "parameter 2",
				severity1 = "Critical",
				severity2 = "High",
				description1 = "description 1",
				description2 = "description 2",
				line1 = "1";
		
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", manualUploadPage.getH2Tag().contains("New Finding"));
		
		applicationDetailPage = manualUploadPage.fillAllClickSaveStatic(true, cwe1, path1, line1, param1, severity1, description1);	
		
		editPage = applicationDetailPage.clickVulnLink(1).clickEditLink();
		
		assertTrue("Parameter didn't make it.", param1.equals(editPage.getParameter()));
		assertTrue("URL didn't make it.", path1.equals(editPage.getSourceFile()));
		assertTrue("Line # didn't make it.", line1.equals(editPage.getLineNumber()));
		assertTrue("Severity didn't make it.", severity1.equals(editPage.getSeverity()));
		assertTrue("CWE didn't make it.", cwe1.equals(editPage.getCWE()));
		assertTrue("Description didn't make it.", description1.equals(editPage.getDescription()));
		
		editPage = editPage.fillAllClickSaveDynamic(true, cwe2, path2, param2, severity2, description2)
				.clickVulnLink(1).clickEditLink();
		
		assertTrue("Parameter didn't make it the second time.", param2.equals(editPage.getParameter()));
		assertTrue("URL didn't make it the second time.", path2.equals(editPage.getURL()));
		assertTrue("Severity didn't make it the second time.", severity2.equals(editPage.getSeverity()));
		assertTrue("CWE didn't make it the second time.", cwe2.equals(editPage.getCWE()));
		assertTrue("Description didn't make it the second time.", description2.equals(editPage.getDescription()));
		
		
		editPage = editPage.fillAllClickSaveStatic(true, cwe1, path1, line1, param1, severity1, description1)
				.clickVulnLink(1).clickEditLink();
		
		assertTrue("Parameter didn't make it the third time.", param1.equals(editPage.getParameter()));
		assertTrue("URL didn't make it the third time.", path1.equals(editPage.getSourceFile()));
		assertTrue("Line # didn't make it the third time.", line1.equals(editPage.getLineNumber()));
		assertTrue("Severity didn't make it the third time.", severity1.equals(editPage.getSeverity()));
		assertTrue("CWE didn't make it the third time.", cwe1.equals(editPage.getCWE()));
		assertTrue("Description didn't make it the third time.", description1.equals(editPage.getDescription()));
		
		editPage.clickStaticSubmit().clickDeleteLink().clickDeleteButton().logout();
	}
	*/
	/*
	@Test
	public void testEditValidation() {
		String cwe1 = GenericVulnerability.CWE_CROSS_SITE_SCRIPTING, 
				path1 = "/normal/first/path.jsp",
				param1 = "parameter 1",
				severity1 = "Critical",
				description1 = "description 1";
		
		manualUploadPage = getToManualSubmissionPage(getRandomString(15),getRandomString(15));
		assertTrue("Manual Finding Submission Page Not Found", 
				manualUploadPage.getH2Tag().contains("New Finding"));
		
		applicationDetailPage = manualUploadPage.fillAllClickSaveDynamic(
				true, cwe1, path1, param1, severity1, description1);	
		
		editPage = applicationDetailPage.clickVulnLink(1).clickEditLink();
		
		assertTrue("Parameter didn't make it.", param1.equals(editPage.getParameter()));
		assertTrue("URL didn't make it.", path1.equals(editPage.getURL()));
		assertTrue("Severity didn't make it.", severity1.equals(editPage.getSeverity()));
		assertTrue("CWE didn't make it.", cwe1.equals(editPage.getCWE()));
		assertTrue("Description didn't make it.", description1.equals(editPage.getDescription()));
		
		editPage = editPage.setCWE("").setDescription("").clickDynamicSubmitInvalid();
		
		assertTrue("Error message not displayed.", 
				editPage.getChannelVulnError().equals("Vulnerability is a required field."));
	
		assertTrue("Description Error not found.", 
				editPage.getDescriptionError().equals("Description is a required field."));
		
		editPage = editPage
				.clickBack()
				.clickVulnLink(1)
				.clickEditLink()
				.clickStaticRadioButton()
				.setLineNumber("NOT A NUMBER")
				.clickStaticSubmitInvalid();
		
		assertTrue("Line Number format message not found.", 
				editPage.getLineNumberError().equals("Line number is invalid."));
		
		editPage = editPage
				.clickBack()
				.clickVulnLink(1)
				.clickEditLink()
				.setCWE("NOT A CWE")
				.clickDynamicSubmitInvalid();
		
		assertTrue("Error message not displayed.", 
				editPage.getChannelVulnError().equals("Vulnerability is invalid."));
	
		editPage.clickBack().clickDeleteLink().clickDeleteButton().logout();
	}
	*/
	
	/*
	private ManualUploadPage getToManualSubmissionPageOLD(String orgName, String appName) {
		return loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.addNewApplication(teamName, appName, urlText, "Low")
				
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(orgName)
				.addNewTeam()
				.clickAddApplicationLink()
				.setNameInput(appName)
				.setUrlInput("http://")
				.clickAddApplicationButton()
				.clickAddFindingManuallyLink();
	}
	*/
	/*
	private ManualUploadPage getToManualSubmissionPage(String teamName, String appName) {
		return loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.addNewApplication(teamName, appName, "http://test.com", "Low")
				//.ManualSubmissionPage;
	}
			*/
}
