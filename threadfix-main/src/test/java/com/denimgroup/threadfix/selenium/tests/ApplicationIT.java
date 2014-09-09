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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.context.ApplicationContextAware;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class ApplicationIT extends BaseIT {

	@Test 
	public void testCreateBasicApplicationDisplayedTeamIndexPage() {
		String teamName = "testCreateBasicApplicationTeam" + getRandomString(3);
		String appName = "testCreateBasicApplicationApp" + getRandomString(3);
		String urlText = "http://testurl.com";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        teamIndexPage.expandTeamRowByName(teamName)
				.addNewApplication(teamName, appName, urlText, "Low")
				.saveApplication();

        assertTrue("The application was not added properly.", teamIndexPage.isAppPresent(teamName, appName));
	}

    @Test
    public void testCreateBasicApplicationDisplayedApplicationDetailPage() {
        String teamName = "TeamName" + getRandomString(3);
        String appName = "AppName" + getRandomString(3);
        String urlText = "http://testurl.com";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        //Create Application
        ApplicationDetailPage ap = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, urlText, "Low")
                .saveApplication()
                .clickViewAppLink(appName, teamName);

        assertTrue("The name was not preserved correctly on Application Detail Page.",
                ap.getNameText().contains(appName));
    }

    @Test
    public void testCreateBasicAppFromTeamDetailPage() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String url = "http://testurl.com";
        String criticality = "Low";

        DatabaseUtils.createTeam(teamName);

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewTeamLink(teamName);

        teamDetailPage.clickAddApplicationButton()
                .setApplicationInfo(appName, url, criticality)
                .clickModalSubmit();

        assertTrue("Application was not present on team's detail page.", teamDetailPage.isAppPresent(appName));

        ApplicationDetailPage applicationDetailPage = teamDetailPage.clickAppLink(appName);

        assertTrue("Application name was not present on application's detail page.",
                applicationDetailPage.getNameText().equals(appName));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("Application was not present on team index page.", teamIndexPage.isAppPresent(teamName, appName));
    }

    /*___________________________ Validation ___________________________*/
	@Test 
	public void testCreateBasicApplicationValidation() {
        String teamName = "testCreateBasicApplicationValidationTeam" + getRandomString(3);
		
		String emptyError = "Name is required.";
        String notValidURl = "URL is invalid.";
        String maximumLengthError = "Maximum length is 60.";
		
		String emptyString = "";
        String brokenURL = "asdckjn.com";
		String whiteSpace = "     ";
        String tooLong = getRandomString(61);

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

		//Team & Application set up...hopefully to be removed later
		teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, emptyString, emptyString, "Low")
                .saveApplicationInvalid();
		
		assertTrue("The correct error did not appear for the name field.",
                teamIndexPage.getNameRequiredMessage().contains(emptyError));

        teamIndexPage.setApplicationName(tooLong)
                .saveApplicationInvalid();

        assertTrue("The correct error did not appear for the name field.",
                teamIndexPage.getNameLengthMessage().contains(maximumLengthError));
		
		teamIndexPage = teamIndexPage.clickCloseAddAppModal()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, whiteSpace, brokenURL, "Low")
                .saveApplicationInvalid();

		assertTrue("The correct error did not appear for the name field.",
                teamIndexPage.getNameRequiredMessage().contains(emptyError));

		assertTrue("The correct error did not appear for the url field.", 
				teamIndexPage.getUrlErrorMessage().contains(notValidURl));

    }

    @Test
    public void testCreateBasicApplicationDuplicateValidation() {
        String teamName = "teamName" + getRandomString(3);
        String appName = "appName" + getRandomString(3);

        String duplicateError = "That name is already taken.";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, "http://dummyurl", "Low")
                .saveApplicationInvalid();

		assertTrue("The duplicate message didn't appear correctly.", 
				teamIndexPage.getNameTakenErrorMessage().contains(duplicateError));
	}

	@Test
	public void testEditBasicApplicationDisplayedApplicationDetailPage() {
		String teamName = "testCreateBasicApplicationTeam" + getRandomString(3);
		String appName1 = "testCreateBasicApplicationApp" + getRandomString(3);
		String urlText1 = "http://testurl.com";
		String appName2 = "testCreateBasicApplicationApp" + getRandomString(3);
		String urlText2 = "http://testurl.com352";

        DatabaseUtils.createTeam(teamName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
				.addNewApplication(teamName, appName1, urlText1, "Low")
				.saveApplication()
				.clickViewAppLink(appName1, teamName);

		applicationDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .setNameInput(appName2)
				.setUrlInput(urlText2)
				.clickUpdateApplicationButton();

        applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName2, teamName);
		
		assertTrue("The name was not preserved correctly on Application Detail Page.",
                appName2.equals(applicationDetailPage.getNameText()));

        applicationDetailPage.clickEditDeleteBtn();
	    assertTrue("The URL was not edited correctly.", applicationDetailPage.getUrlText().contains(urlText2));
	}

    @Test
    public void testEditBasicApplicationDisplayedTeamIndexPage() {
        String teamName = "testCreateBasicApplicationTeam" + getRandomString(3);
        String appName1 = "testCreateBasicApplicationApp" + getRandomString(3);
        String urlText1 = "http://testurl.com";
        String appName2 = "testCreateBasicApplicationApp" + getRandomString(3);
        String urlText2 = "http://testurl.com352";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName1, urlText1, "Low")
                .saveApplication();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName1, teamName);

        applicationDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .setNameInput(appName2)
                .setUrlInput(urlText2)
                .clickUpdateApplicationButton();

        // ensure that the application is present in the organization's app table.
        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The edited application does not appear on Team Index Page.", teamIndexPage.isAppPresent(teamName,appName2));
    }

	@Test
	public void testEditBasicApplicationValidation() {
        String teamName = "testEditBasicApplicationValidationTeam" + getRandomString(3);
		String appName2 = "testApp23";
		String appName = "testApp17";
		String validUrlText = "http://test.com";
		String urlText = "htnotaurl.com";
		
		StringBuilder stringBuilder = new StringBuilder("");
		for (int i = 0; i < Application.NAME_LENGTH + 50; i++) { stringBuilder.append('i'); }
		String longInputName = stringBuilder.toString();
		
		stringBuilder = new StringBuilder("");
		for (int i = 0; i < Application.URL_LENGTH + 50; i++) { stringBuilder.append('i'); }
		String longInputUrl = "http://" + stringBuilder.toString();
		
		String emptyError = "Name is required.";
		
		String emptyString = "";
		String whiteSpace = "     ";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();
		
		//set up an organization,
		//add an application for duplicate checking,
		//add an application for normal testing,
		// and Test a submission with no changes
		teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName2, validUrlText, "Low")
                .saveApplication()
                .clickOrganizationHeaderLink();

        teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, validUrlText, "Low")
                .saveApplication()
                .clickOrganizationHeaderLink();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        sleep(2000);
		// Test blank input
		applicationDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .setNameInput(emptyString)
                .setUrlInput(emptyString)
                .clickUpdateApplicationButtonInvalid();
		
		assertTrue("The correct error did not appear for the name field.", 
				applicationDetailPage.getNameRequiredError().equals(emptyError));

		// Test URL format
		applicationDetailPage = applicationDetailPage.clickCloseAppInvalid()
                .clickEditDeleteBtn()
                .setNameInput("dummyName")
                .setUrlInput(urlText)
                .clickUpdateApplicationButtonInvalid();

		assertTrue("The correct error did not appear for the url field.",
				applicationDetailPage.getUrlError().equals("URL is invalid."));

        /*  Need to Fix name lengths to work correctly
		// Test browser field length limits
		applicationDetailPage = applicationDetailPage.setNameInput(longInputName)
                .setUrlInput(longInputUrl)
                .clickUpdateApplicationButton()
                .clickEditDeleteBtn();

        //Is this even good?
		assertTrue("The length limit was incorrect for name.", 
				applicationDetailPage.getNameText().length() == Application.NAME_LENGTH);
	    */
	}

	@Test
	public void testAddWafAtApplicationCreationTimeAndDelete() {
		String wafName = "appCreateTimeWaf1";
		String type = "Snort";
		String teamName = "appCreateTimeWafOrg2";
		String appName = "appCreateTimeWafName2";
		String appUrl = "http://testurl.com";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        WafIndexPage wafIndexPage = teamIndexPage.clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName, type)
                .clickCreateWaf();

		// Add Application with WAF
        ApplicationDetailPage applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, appUrl, "Low")
                .saveApplication()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickAddWaf()
                .addWaf(wafName)
                .clickUpdateApplicationButton();


		// Check that it also appears on the WAF page.
        WafRulesPage wafDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .clickWafsHeaderLink()
                .clickRules(wafName);
		
		assertTrue("The WAF was not added correctly.", 
				wafDetailPage.isTextPresentInApplicationsTableBody(appName));
		
		// Attempt to delete the WAF and ensure that it is a failure because the Application is still there
		// If the page goes elsewhere, this call will fail.
		wafIndexPage = wafDetailPage.clickOrganizationHeaderLink()
                .clickWafsHeaderLink()
                .clickDeleteWaf(wafName);
		
		// Delete app and org and make sure the Application doesn't appear in the WAFs table.
		wafDetailPage = wafIndexPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickDeleteButton()
                .clickWafsHeaderLink()
                .clickRules(wafName);
		
		assertFalse("The Application was not removed from the WAF correctly.", 
				wafDetailPage.isTextPresentInApplicationsTableBody(appName));
		
		loginPage = wafDetailPage.clickWafsHeaderLink().clickDeleteWaf(wafName).logout();
		
	}

	@Test
	public void testSwitchWafs() {
		String wafName1 = "firstWaf" + getRandomString(3);
		String wafName2 = "secondWaf" + getRandomString(3);
		String type1 = "Snort" ;
		String type2 = "mod_security";
		String teamName = "testSwitchWafs" + getRandomString(3);
		String appName = "switchWafApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        WafIndexPage wafIndexPage = teamIndexPage.clickWafsHeaderLink()
                .clickAddWafLink()
                .setWafName(wafName1)
                .setWafType(type1)
                .clickCreateWaf()
                .clickAddWafLink()
                .setWafName(wafName2)
                .setWafType(type2)
                .clickCreateWaf();

        ApplicationDetailPage applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickAddWaf()
                .addWaf(wafName1)
                .saveWafAdd()
                .clickUpdateApplicationButton();

        TeamIndexPage ti = applicationDetailPage.clickOrganizationHeaderLink();

        ApplicationDetailPage apt = ti.expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickAddWaf()
                .addWaf(wafName2)
                .saveWafAdd()
                .clickUpdateApplicationButton()
                .clickEditDeleteBtn();

        assertTrue("Did not properly save changing of Wafs.", apt.getWafText().contains(wafName2));
	}

	@Test
	public void sameAppNameMultipleTeams(){
		String appName = getRandomString(8);
		String teamName1 = getRandomString(8);
		String teamName2 = getRandomString(8);

        DatabaseUtils.createTeam(teamName1);
        DatabaseUtils.createApplication(teamName1, appName);
        DatabaseUtils.createTeam(teamName2);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        //Add an app with same name to both teams
        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName2)
				.addNewApplication(teamName2, appName, "", "Low")
				.saveApplication()
				.expandTeamRowByName(teamName1)
				.clickViewAppLink(appName,teamName1);
		
		Boolean isAppInTeam1 = applicationDetailPage.getNameText().contains(appName);
		
		applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName2)
				.clickViewAppLink(appName, teamName2);
		
		Boolean isAppInTeam2  = applicationDetailPage.getNameText().contains(appName);

		assertTrue("Unable to add apps with the same name to different teams", isAppInTeam1 && isAppInTeam2);
	}

    @Test
    public void switchTeamTest() {
        String teamName1 = "switchAppTeam" + getRandomString(3);
        String teamName2 = "switchAppTeam" + getRandomString(3);
        String appName = "switchApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName1);
        DatabaseUtils.createTeam(teamName2);
        DatabaseUtils.createApplication(teamName1, appName);

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        teamIndexPage.expandTeamRowByName(teamName1);
        ApplicationDetailPage applicationDetailpage = teamIndexPage.clickViewAppLink(appName, teamName1);
        sleep(2000);
        applicationDetailpage.clickEditDeleteBtn();
        applicationDetailpage.setTeam(teamName2);
        applicationDetailpage.clickUpdateApplicationButton();

        applicationDetailpage.clickOrganizationHeaderLink();
        TeamDetailPage teamDetailPage = teamIndexPage.clickViewTeamLink(teamName1);

        Boolean appOnTeam1 = teamDetailPage.isAppPresent(appName);

        teamDetailPage = teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName2);

        Boolean appOnTeam2 = teamDetailPage.isAppPresent(appName);

        assertTrue("The application was not switched properly.", !appOnTeam1 && appOnTeam2);
    }

    /*___________________________ Manual Findings ___________________________*/
    @Test
    public void testAddDynamicManualFinding() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String cwe = "Improper Validation of Certificate Expiration";
        String parameter = "Test Parameter";
        String description = "Test Description.";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .setCWE(cwe)
                .setParameter(parameter)
                .setDescription(description)
                .clickDynamicSubmit();

        assertTrue("Manual finding was not added to vulnerabilities listing on application detail page.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "1"));

        FindingDetailPage findingDetailPage = applicationDetailPage.clickScansTab()
                .clickViewScan()
                .clickViewFinding();

        assertTrue("Finding description did not match the given input.",
                description.equals(findingDetailPage.getDetail("longDescription")));
        assertTrue("Finding parameter did not match the given input.",
                parameter.equals(findingDetailPage.getDetail("parameter")));
        assertTrue("Finding CWE did not match the given input",
                cwe.equals(findingDetailPage.getDetail("genericVulnerabilityName")));
    }

    @Test
    public void testEditDynamicManualFinding() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String originalCwe = "Improper Validation of Certificate Expiration";
        String editedCwe = "Improper Resolution of Path Equivalence";
        String originalParameter = "testParameter";
        String editedParameter = "testParameter-edited";
        String originalDescription = "Test Description: This is a test, this is only a test.";
        String editedDescription = "Edited Description: This should have been edited.";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .setCWE(originalCwe)
                .setParameter(originalParameter)
                .setDescription(originalDescription)
                .clickDynamicSubmit();

        VulnerabilityDetailPage vulnerabilityDetailPage = applicationDetailPage.clickScansTab()
                .clickViewScan()
                .clickViewFinding()
                .clickViewVulnerability()
                .clickEditFinding()
                .setCwe(editedCwe)
                .setDescription(editedDescription)
                .setParameter(editedParameter)
                .clickModalSubmit();

        FindingDetailPage findingDetailPage = vulnerabilityDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScansTab()
                .clickViewScan()
                .clickViewFinding();

        assertTrue("Scanner Vulnerability did not match the given input.",
                editedCwe.equals(findingDetailPage.getDetail("scannerVulnerabilityType")));
        assertTrue("Finding description did not match the given input.",
                editedDescription.equals(findingDetailPage.getDetail("longDescription")));
        assertTrue("Finding parameter did not match the given input.",
                editedParameter.equals(findingDetailPage.getDetail("parameter")));
    }


    @Test
    public void testAddStaticManualFinding() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String cwe = "Improper Validation of Certificate Expiration";
        String parameter = "Test Parameter";
        String description = "Test Description.";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .clickStaticRadioButton()
                .setCWE(cwe)
                .setParameter(parameter)
                .setDescription(description)
                .clickDynamicSubmit();

        assertTrue("Manual finding was not added to vulnerabilities listing on application detail page.",
                applicationDetailPage.isVulnerabilityCountCorrect("Critical", "1"));

        FindingDetailPage findingDetailPage = applicationDetailPage.clickScansTab()
                .clickViewScan()
                .clickViewFinding();

        assertTrue("Finding description did not match the given input.",
                description.equals(findingDetailPage.getDetail("longDescription")));
        assertTrue("Finding parameter did not match the given input.",
                parameter.equals(findingDetailPage.getDetail("parameter")));
        assertTrue("Finding CWE did not match the given input",
                cwe.equals(findingDetailPage.getDetail("genericVulnerabilityName")));
    }

    @Test
    public void testEditStaticManualFinding() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String originalCwe = "Improper Validation of Certificate Expiration";
        String editedCwe = "Improper Resolution of Path Equivalence";
        String originalParameter = "testParameter";
        String editedParameter = "testParameter-edited";
        String originalDescription = "Test Description: This is a test, this is only a test.";
        String editedDescription = "Edited Description: This should have been edited.";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .clickStaticRadioButton()
                .setCWE(originalCwe)
                .setParameter(originalParameter)
                .setDescription(originalDescription)
                .clickDynamicSubmit();

        VulnerabilityDetailPage vulnerabilityDetailPage = applicationDetailPage.clickScansTab()
                .clickViewScan()
                .clickViewFinding()
                .clickViewVulnerability()
                .clickEditFinding()
                .setCwe(editedCwe)
                .setDescription(editedDescription)
                .setParameter(editedParameter)
                .clickModalSubmit();

        FindingDetailPage findingDetailPage = vulnerabilityDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScansTab()
                .clickViewScan()
                .clickViewFinding();

        assertTrue("Scanner Vulnerability did not match the given input.",
                editedCwe.equals(findingDetailPage.getDetail("scannerVulnerabilityType")));
        assertTrue("Finding description did not match the given input.",
                editedDescription.equals(findingDetailPage.getDetail("longDescription")));
        assertTrue("Finding parameter did not match the given input.",
                editedParameter.equals(findingDetailPage.getDetail("parameter")));
    }

    //TODO add validation test for static manual finding modal
    @Test
    public void deleteManualFindingScan() {
        String teamName = "TeamName" + getRandomString(5);
        String appName = "AppName" + getRandomString(5);
        String CWE = "79";
        String url = "http://test.com";
        String desc = "Test Description for deleting manual finding.";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        sleep(3000);
        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .setCWE(CWE)
                .setURL(url)
                .setDescription(desc)
                .clickDynamicSubmit();

        applicationDetailPage.clickScansTab()
                .clickDeleteScanButton();

        assertTrue("Manual Finding was not deleted correctly.", applicationDetailPage.isScanDeleted());

    }

    /*___________________________ Deletion ___________________________*/

    @Test
    public void deleteUploadedScan() {
        String teamName = "TeamName" + getRandomString(5);
        String appName = "AppName" + getRandomString(5);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage ap = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        ap.clickScansTab()
                .clickDeleteScanButton();

        assertTrue("Scan file was not deleted correctly.", ap.isScanDeleted());
    }

    @Test
    public void deleteApplicationTest() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        TeamDetailPage teamDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .clickDeleteLink();

        assertFalse("Application is still present on team's detail page.", teamDetailPage.isAppPresent(appName));

        TeamIndexPage teamIndexPage = teamDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertFalse("Application is still present on the team index page.", teamIndexPage.isAppPresent(teamName, appName));
    }

    @Test
    public void remoteSourceCodeTest() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);

        String repositoryURL = "http://test.com";
        String repositoryRevision = "QA";
        String repositoryUserName = "user";
        String repositoryPassword = "password";

        TeamIndexPage teamIndexPage = loginPage.login("user","password")
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName,appName,"http://testapp.com","Low")
                .addRemoteSourceCodeInformation(repositoryURL, repositoryRevision, repositoryUserName, repositoryPassword)
                .clickModalSubmit();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .expandSourceCodeFields();

        assertTrue("Repository URL was not saved properly.",
                applicationDetailPage.isRepositoryURLCorrect(repositoryURL));
        assertTrue("Repository Revision was not saved properly.",
                applicationDetailPage.isRepositoryRevisionCorrect(repositoryRevision));
        assertTrue("Repository User Name was not saved properly",
                applicationDetailPage.isRepositoryUserNameCorrect(repositoryUserName));
        assertFalse("Repository Password was not saved properly",
                applicationDetailPage.isRepositoryPasswordEmpty());
    }


    @Test
    public void editSourceCodeTest() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);

        String repositoryURL = "http://test.com";
        String repositoryRevision = "QA";
        String repositoryUserName = "user";
        String repositoryPassword = "password";

        String repositoryURLEdited = "http://test2.com";
        String repositoryRevisionEdited = "QA2";
        String repositoryUserNameEdited = "user2";
        String repositoryPasswordEdited = "password2";

        TeamIndexPage teamIndexPage = loginPage.login("user","password")
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName,appName,"http://testapp.com","Low")
                .addRemoteSourceCodeInformation(repositoryURL, repositoryRevision, repositoryUserName, repositoryPassword)
                .clickModalSubmit();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .expandSourceCodeFields()
                .setRemoteSourceCodeInformation(repositoryURLEdited, repositoryRevisionEdited, repositoryUserNameEdited, repositoryPasswordEdited)
                .clickModalSubmit();

        applicationDetailPage.clickEditDeleteBtn()
                  .expandSourceCodeFields();

        assertTrue("Repository URL was not saved properly.",
                applicationDetailPage.isRepositoryURLCorrect(repositoryURLEdited));
        assertTrue("Repository Revision was not saved properly.",
                applicationDetailPage.isRepositoryRevisionCorrect(repositoryRevisionEdited));
        assertTrue("Repository User Name was not saved properly",
                applicationDetailPage.isRepositoryUserNameCorrect(repositoryUserNameEdited));
        assertFalse("Repository Password was not saved properly",
                applicationDetailPage.isRepositoryPasswordEmpty());
    }

    @Test
    public void localSourceCodeTest() {

        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);

        String repositoryPath = System.getProperty("sourceCodeLocation");

        TeamIndexPage teamIndexPage = loginPage.login("user","password")
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName,appName,"http://testapp.com","High")
                .setSourceCodeFolder(repositoryPath)
                .clickModalSubmit();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .expandSourceCodeFields();

        assertTrue("Repository Path was not saved properly",
                applicationDetailPage.isRepositoryPathEmpty(repositoryPath));
    }

    @Test
    public void createAppSourceCodeValidate() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);

        String repositoryURL = "htt://test.com";

        TeamIndexPage teamIndexPage = loginPage.login("user","password")
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName,appName,"http://testapp.com","Low")
                .setRemoteSourceCodeURL(repositoryURL);

        assertTrue("The correct error did not appear for the url field.",
                teamIndexPage.getUrlRepositoryError().equals("URL is invalid."));
        assertFalse("Add Application Button is clickable",
                teamIndexPage.isAddApplicationButtonClickable());

    }

    @Test
    public void editApplicationSourceCodeValidation() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);

        String repositoryURL = "http://test.com";
        String repositoryURLEdited = "htp://test1.com";

        TeamIndexPage teamIndexPage = loginPage.login("user","password")
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName,appName,"http://testapp.com","Low")
                .setRemoteSourceCodeURL(repositoryURL)
                .clickModalSubmit();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName,teamName)
                .clickEditDeleteBtn()
                .expandSourceCodeFields()
                .setRepositoryURLEdited(repositoryURLEdited)
                .clickUpdateApplicationButtonInvalid();

        assertTrue("The correct error did not appear for the url field.",
                applicationDetailPage.getUrlRepositoryError().equals("URL is invalid."));
        assertFalse("Add Application Button is clickable",
                applicationDetailPage.isApplicationSaveChangesButtonClickable());
    }

    @Test
    public void createApplicationNewWaf() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        String wafName = getRandomString(8);

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickSetWaf();

        if (applicationDetailPage.isWafPresent()) {
                    applicationDetailPage.clickCreateNewWaf()
                        .setWafName(wafName)
                        .clickCreateWAfButtom()
                        .clickModalSubmit();
        } else {
            applicationDetailPage.setWafName(wafName)
                    .clickCreateWAfButtom()
                    .clickModalSubmit();
        }

        applicationDetailPage.clickEditDeleteBtn();

        assertTrue("The correct error did not appear for the url field.",
                applicationDetailPage.checkWafName().equals(wafName));
    }

    @Test
    public void switchWafOnApplications() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String type = "Snort";
        String wafName1 = getRandomString(8);
        String wafName2 = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName1,type)
                .clickCreateWaf()
                .clickAddWafLink()
                .createNewWaf(wafName2,type)
                .clickCreateWaf();

        // Assign WAf to the application
        ApplicationDetailPage applicationDetailPage = wafIndexPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickSetWaf()
                .addWaf(wafName1)
                .clickUpdateApplicationButton()
                .clickModalSubmit();

        //switch from the first WAF to the second WAF
        applicationDetailPage.clickEditDeleteBtn()
                .clickSetWaf()
                .addWaf(wafName2)
                .clickUpdateApplicationButton()
                .clickModalSubmit();

        applicationDetailPage.clickEditDeleteBtn()
                .checkWafName();

        assertTrue("The WAF wasn't switch correctly",
                applicationDetailPage.checkWafName().equals(wafName2));
    }

    @Test
    public void removeWaf() {
        String type = "Snort";
        String wafName1 = getRandomString(8);

        WafIndexPage wafIndexPage = loginPage.login("user", "password")
                .clickWafsHeaderLink()
                .clickAddWafLink()
                .createNewWaf(wafName1,type)
                .clickCreateWaf()
                .clickDeleteWaf(wafName1);

        assertFalse("The Application was not removed from the WAF correctly.",
                wafIndexPage.isWafPresent(wafName1));
    }

    @Test
    public void generateWafRules() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String wafName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickSetWaf();

        if (applicationDetailPage.isWafPresent()) {
            applicationDetailPage.clickCreateNewWaf()
                    .setWafName(wafName)
                    .clickCreateWAfButtom()
                    .clickModalSubmit();
        } else {
            applicationDetailPage.setWafName(wafName)
                    .clickCreateWAfButtom()
                    .clickModalSubmit();
        }

        WafIndexPage wafIndexPage = applicationDetailPage.clickWafsHeaderLink();

        WafRulesPage wafRulesPage = wafIndexPage.clickRules(wafName)
                .clickGenerateWafRulesButton();

        assertTrue("WAf Rule does not exist",
                wafRulesPage.isDownloadWafRulesDisplay());
    }

    @Test
    public void uploadLogFile() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String wafName = getRandomString(8);
        String logFile = ScanContents.SCAN_FILE_MAP.get("Snort Log");

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickSetWaf();

        if (applicationDetailPage.isWafPresent()) {
            applicationDetailPage.clickCreateNewWaf()
                    .setWafName(wafName)
                    .clickCreateWAfButtom()
                    .clickModalSubmit();
        } else {
            applicationDetailPage.setWafName(wafName)
                    .clickCreateWAfButtom()
                    .clickModalSubmit();
        }

        WafIndexPage wafIndexPage = applicationDetailPage.clickWafsHeaderLink();

        WafRulesPage wafRulesPage = wafIndexPage.clickRules(wafName)
                .clickGenerateWafRulesButton();

        wafRulesPage.refreshPage();

        wafRulesPage.setLogFile(logFile);

        WafLogPage wafLogPage = wafRulesPage.clickUploadLogFile();

        wafLogPage.clickContinue();

        wafIndexPage.clickRules(wafName);

        wafRulesPage.clickViewDetails();

        assertTrue("Logs are available", wafRulesPage.isLogsNumberPresent());
    }

    @Test
    public void checkunmappedFindingsLink() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Unmapped Scan"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        FindingDetailPage findingDetailPage = applicationDetailPage.clickUnmappedFindings()
                .clickUnmappedViewFinding();

        assertTrue("Finding Detail Page is not valid", findingDetailPage.isScannerVulnerabilityTextPresent());
    }

    @Test
    public void uploadNewScan() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName,appName);

        String newScan = ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan");

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickActionButton()
                .clickUploadScan()
                .uploadScan(newScan);
        assertTrue("Scan didnt Upload",applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
    }
    @Test
    public void uploadSameScanTwiceOnApplicationPage() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String newScan = ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan");

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickActionButton()
                .clickUploadScan()
                .uploadScan(newScan);

        assertTrue("The first scan hasn't uploaded yet", applicationDetailPage.isScanUploadedAlready(teamName, appName));
    }

    public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
