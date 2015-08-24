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
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class ApplicationIT extends BaseDataTest {

    //===========================================================================================================
    // Application Creation, Deletion, and Editing
    //===========================================================================================================

    //TODO: Evaluate what test class these tests should belong to.
    @Test
    public void testCreatedApplicationIsPresentOnTeamIndexPage() {
        String teamName = createTeam();
        String appName = getName();
        String urlText = "http://testurl.com";

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();

        teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, urlText, "Low")
                .saveApplication();

        assertTrue("The application was not added properly.", teamIndexPage.isAppPresent(teamName, appName));
    }

    @Test
    public void testAppShowsCorrectNameOnApplicationDetailPage() {
        String teamName = createTeam();
        String appName = getName();
        String urlText = "http://testurl.com";

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();

        //Create Application
        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, urlText, "Low")
                .saveApplication()
                .clickViewAppLink(appName, teamName);

        assertTrue("The name was not preserved correctly on Application Detail Page.",
                applicationDetailPage.getNameText().contains(appName));
    }

    @Test
    public void testCreateAppFromTeamDetailPage() {
        String teamName = createTeam();
        String appName = getName();
        String url = "http://testurl.com";
        String criticality = "Low";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewTeamLink(teamName);

        teamDetailPage.clickAddApplicationButton()
                .setApplicationInfo(appName, url, criticality)
                .clickModalSubmit();

        assertTrue("Application was not present on team's detail page.", teamDetailPage.isAppPresent(appName));

        ApplicationDetailPage applicationDetailPage = teamDetailPage.clickAppLink("0");

        assertTrue("Application name was not present on application's detail page.",
                applicationDetailPage.getNameText().equals(appName));

        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("Application was not present on team index page.", teamIndexPage.isAppPresent(teamName, appName));
    }

    @Test
    public void testApplicationCreationFieldValidation() {
        String teamName = createTeam();

        String emptyError = "Name is required.";
        String notValidURl = "URL is invalid.";
        String maximumLengthError = "Maximum length is 60.";

        String emptyString = "";
        String brokenURL = "asdckjn.com";
        String whiteSpace = "     ";
        String tooLong = getRandomString(61);

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
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
    public void testPreventDuplicateApplicationCreation() {
        initializeTeamAndApp();

        String duplicateError = "That name is already taken.";

        TeamIndexPage teamIndexPage = loginPage.defaultLogin().
                clickOrganizationHeaderLink();

        teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, "http://dummyurl", "Low")
                .saveApplicationInvalid();

        assertTrue("The duplicate message didn't appear correctly.",
                teamIndexPage.getNameTakenErrorMessage().contains(duplicateError));
    }

    @Test
    public void testEditApplicationFieldValidation() {
        String teamName = getName();
        String appName2 = "testApp23";
        String appName = "testApp17";
        String validUrlText = "http://test.com";
        String urlText = "htnotaurl.com";

        StringBuilder stringBuilder = new StringBuilder("");
        for (int i = 0; i < Application.NAME_LENGTH + 50; i++) {
            stringBuilder.append('i');
        }
        String longInputName = stringBuilder.toString();

        stringBuilder = new StringBuilder("");
        for (int i = 0; i < Application.URL_LENGTH + 50; i++) {
            stringBuilder.append('i');
        }
        String longInputUrl = "http://" + stringBuilder.toString();

        String emptyError = "Name is required.";

        String emptyString = "";
        String whiteSpace = "     ";

        DatabaseUtils.createTeam(teamName);

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
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
        applicationDetailPage = applicationDetailPage.clickCloseModalButton()
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
    public void testCreateAppWithSameNameForMultipleTeams() {
        initializeTeamAndApp();
        String teamName2 = createTeam();

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();

        //Add an app with same name to both teams
        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName2)
                .addNewApplication(teamName2, appName, "", "Low")
                .saveApplication()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        Boolean isAppAttachedToTeam1 = applicationDetailPage.getNameText().contains(appName);

        applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName2)
                .clickViewAppLink(appName, teamName2);

        Boolean isAppAttachedToTeam2 = applicationDetailPage.getNameText().contains(appName);

        assertTrue("Unable to add apps with the same name to different teams", isAppAttachedToTeam1 && isAppAttachedToTeam2);
    }

    @Test
    public void testDeleteApplication() {
        initializeTeamAndApp();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
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
    public void testEditedApplicationInfoPresentOnApplicationDetailPage() {
        initializeTeamAndApp();
        String appNameEdited = getName();
        String urlText2 = "http://testurl.com352";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .setNameInput(appNameEdited)
                .setUrlInput(urlText2)
                .clickUpdateApplicationButton();

        applicationDetailPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appNameEdited, teamName);

        assertTrue("The name was not preserved correctly on Application Detail Page.",
                appNameEdited.equals(applicationDetailPage.getNameText()));

        applicationDetailPage.clickEditDeleteBtn();
        assertTrue("The URL was not edited correctly.", applicationDetailPage.getUrlText().contains(urlText2));
    }

    @Test
    public void testEditedApplicationInfoPresentOnTeamIndexPage() {
        initializeTeamAndApp();
        String appNameEdited = getName();
        String urlText2 = "http://testurl.com352";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage = applicationDetailPage.clickEditDeleteBtn()
                .setNameInput(appNameEdited)
                .setUrlInput(urlText2)
                .clickUpdateApplicationButton();

        // ensure that the application is present in the organization's app table.
        TeamIndexPage teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("The edited application does not appear on Team Index Page.", teamIndexPage.isAppPresent(teamName, appNameEdited));
    }

    @Test
    public void testAttachAppToADifferentTeam() {
        initializeTeamAndApp();
        String teamName2 = createTeam();

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        ApplicationDetailPage applicationDetailpage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .setTeam(teamName2)
                .clickUpdateApplicationButton();

        TeamDetailPage teamDetailPage = applicationDetailpage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName);

        //Runtime Fix
        sleep(5000);

        Boolean isAppAttachedToTeam1 = teamDetailPage.isAppPresent(appName);

        //Runtime Debug
        if (isAppAttachedToTeam1) { applicationDetailpage.takeScreenShot(); }

        teamDetailPage = teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName2);

        //Runtime Fix
        sleep(5000);

        Boolean isAppAttachedToTeam2 = teamDetailPage.isAppPresent(appName);

        //Runtime Debug
        if (!isAppAttachedToTeam2) { applicationDetailpage.takeScreenShot(); }

        assertTrue("The application was not switched properly.", !isAppAttachedToTeam1 && isAppAttachedToTeam2);
    }

    //===========================================================================================================
    // Manual Findings
    //===========================================================================================================

    @Test
    public void testAddDynamicManualFinding() {
        initializeTeamAndApp();
        String cwe = "Improper Validation of Certificate Expiration";
        String parameter = "Test Parameter";
        String description = "Test Description.";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .setCWE(cwe)
                .setParameter(parameter)
                .setSeverity("Critical")
                .setDescription(description)
                .clickDynamicSubmit()
                .waitForResultsToLoad();

        assertFalse("Manual Finding was not added.", applicationDetailPage.areAllVulnerabilitiesHidden());

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
        initializeTeamAndApp();
        String originalCwe = "Improper Validation of Certificate Expiration";
        String editedCwe = "Improper Resolution of Path Equivalence";
        String originalParameter = "testParameter";
        String editedParameter = "testParameter-edited";
        String originalDescription = "Test Description: This is a test, this is only a test.";
        String editedDescription = "Edited Description: This should have been edited.";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
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
                .toggleVulnInfoSection()
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
        initializeTeamAndApp();
        String cwe = "Improper Validation of Certificate Expiration";
        String parameter = "Test Parameter";
        String description = "Test Description.";
        String sourceFile = "/Test";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .clickStaticRadioButton()
                .setCWE(cwe)
                .setSourceFile(sourceFile)
                .setParameter(parameter)
                .setSeverity("Critical")
                .setDescription(description)
                .clickDynamicSubmit()
                .waitForResultsToLoad();

        assertFalse("Manual Finding was not added.", applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage.refreshPage();

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
        initializeTeamAndApp();
        String originalCwe = "Improper Validation of Certificate Expiration";
        String editedCwe = "Improper Resolution of Path Equivalence";
        String sourceFile = "/test";
        String originalParameter = "testParameter";
        String editedParameter = "testParameter-edited";
        String originalDescription = "Test Description: This is a test, this is only a test.";
        String editedDescription = "Edited Description: This should have been edited.";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .clickStaticRadioButton()
                .setCWE(originalCwe)
                .setSourceFile(sourceFile)
                .setParameter(originalParameter)
                .setDescription(originalDescription)
                .clickDynamicSubmit();

        VulnerabilityDetailPage vulnerabilityDetailPage = applicationDetailPage.clickScansTab()
                .clickViewScan()
                .clickViewFinding()
                .clickViewVulnerability()
                .toggleVulnInfoSection()
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
    public void testDeleteManualFindingScan() {
        initializeTeamAndApp();
        String CWE = "79";
        String url = "http://test.com";
        String desc = "Test Description for deleting manual finding.";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
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

    //TODO Waiting for id's on manual finding form
    @Ignore
    @Test
    public void testManualFindingValidation() {
        initializeTeamAndApp();
        String cwe = "Improper Validation of Certificate Expiration";
        String parameter = "Test Parameter";
        String description = "Test Description.";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .setCWE(cwe)
                .setParameter(parameter)
                .setDescription(description);
        sleep(2000);

        assertTrue("Manual Finding cannot be submitted", applicationDetailPage.isButtonEnabled());

        applicationDetailPage.setCWE("");
        sleep(2000);

        assertTrue("Submitted blank CWE", !applicationDetailPage.isButtonEnabled());

        applicationDetailPage.setCWE("asdfashrhhr");
        sleep(2000);

        assertTrue("Submitted invalid CWE", applicationDetailPage.isCweErrorPresent());

        applicationDetailPage.setCWE(cwe).setParameter("");
        sleep(2000);

        assertTrue("Submitted blank parameter", !applicationDetailPage.isButtonEnabled());

        applicationDetailPage.setParameter(parameter).setDescription("");
        sleep(2000);

        assertTrue("Submitted blank description", !applicationDetailPage.isButtonEnabled());
    }

    //===========================================================================================================
    // Scans
    //===========================================================================================================

    @Test
    public void testDeleteUploadedScan() {
        initializeTeamAndApp();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickScansTab()
                .clickDeleteScanButton();

        assertTrue("Scan file was not deleted correctly.", applicationDetailPage.isScanDeleted());
    }

    @Test
    public void testUploadNewScan() {
        initializeTeamAndApp();

        String newScan = ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan");

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickActionButton()
                .clickUploadScan()
                .uploadScan(newScan);

        assertTrue("Scan didn't Upload", applicationDetailPage.isVulnerabilityCountCorrect("High", "10"));
    }

    @Test
    public void testUploadSameScanTwiceOnApplicationPage() {
        initializeTeamAndApp();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String newScan = ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan");

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickActionButton()
                .clickUploadScan()
                .uploadScan(newScan);

        assertTrue("The first scan hasn't uploaded yet", applicationDetailPage.isScanUploadedAlready(teamName, appName));
    }

    @Test
    public void testDependencyScanInformation() {
        initializeTeamAndApp();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("DependencyCheck"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .expandVulnerabilityByType("High119");

        assertTrue("CVE link wasn't showed", applicationDetailPage.isCveLinkDisplay("0"));
        assertTrue("Component wasn't showed", applicationDetailPage.isCveComponentDisplay("0"));
        assertTrue("Description wasn't showed", applicationDetailPage.isCveDescriptionInputPresent("0"));
    }

    @Test
    public void testCancelDeleteScanAlert() {
        initializeTeamAndApp();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScansTab()
                .cancelDeleteScanButton();

        applicationDetailPage.clickDeleteScanButton();

        assertTrue("Delete Button is still available", applicationDetailPage.isScanDeleted());
    }

    @Test
    public void testFortifySeverityFilterScans() {

        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Fortify AndOrAnd"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        assertTrue("There should be one critical vulnerability.", applicationDetailPage.isVulnerabilityCountCorrect("High", "1"));
        assertTrue("There should be seven high vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("Medium", "7"));
        assertTrue("There should be 24 low vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("Info", "24"));

        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Fortify OrAndOr"));

        applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        assertTrue("There should be one critical vulnerability.", applicationDetailPage.isVulnerabilityCountCorrect("High", "1"));
        assertTrue("There should be seven medium vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("Low", "7"));
        assertTrue("There should be 24 low vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("Info", "24"));

    }

    @Test
    public void testFortifyVulnerabilityCounts() {

        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Fortify NoSeverityFilter"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        assertTrue("There should be twenty high vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("High", "20"));
        assertTrue("There should be sixteen medium vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("Medium", "16"));
        assertTrue("There should be two info vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("Info", "2"));
    }

    //===========================================================================================================
    // Source Code Fields
    //===========================================================================================================

    @Test
    public void testRemoteSourceCode() {
        String teamName = createTeam();
        String appName = getName();

        String repositoryURL = "https://github.com/denimgroup/threadfix";
        String repositoryRevision = "QA";
        String repositoryUserName = "user";
        String repositoryPassword = "password";

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName, appName, "http://testapp.com", "Low")
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
    public void testEditSourceCode() {
        String teamName = createTeam();
        String appName = getName();

        String repositoryURL = "https://github.com/denimgroup/threadfix";
        String repositoryRevision = "QA";
        String repositoryUserName = "user";
        String repositoryPassword = "password";

        String repositoryURLEdited = "https://github.com/denimgroup/threadfix/tree/dev-qa";
        String repositoryRevisionEdited = "QA2";
        String repositoryUserNameEdited = "user2";
        String repositoryPasswordEdited = "password2";

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName, appName, "http://testapp.com", "Low")
                .addRemoteSourceCodeInformation(repositoryURL, repositoryRevision, repositoryUserName, repositoryPassword)
                .clickModalSubmit();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .expandSourceCodeFields()
                .setRemoteSourceCodeInformation(repositoryURLEdited, repositoryRevisionEdited, repositoryUserNameEdited, repositoryPasswordEdited)
                .clickModalSubmitInvalid();

        applicationDetailPage.clickEditDeleteBtn()
                .expandSourceCodeFields();

        sleep(2000);

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
    public void testLocalSourceCode() {
        String teamName = createTeam();
        String appName = getName();

        String repositoryPath = System.getProperty("sourceCodeLocation");

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName, appName, "http://testapp.com", "High")
                .setSourceCodeFolder(repositoryPath)
                .clickModalSubmit();

        assertFalse("Source Code Folder was invalid.", teamIndexPage.isSourceFolderInvalidErrorPresent());

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .expandSourceCodeFields();

        assertFalse("Repository Path was not saved properly",
                applicationDetailPage.isRepositoryPathEmpty());
    }

    //TODO: Update test to reflect new source code functionality.
    @Ignore
    @Test
    public void testEditApplicationSourceCodeValidation() {
        String teamName = createTeam();
        String appName = getName();

        String repositoryURL = "http://test.com";
        String repositoryURLEdited = "htp://test1.com";

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName, appName, "http://testapp.com", "Low")
                .setRemoteSourceCodeURL(repositoryURL)
                .selectGitRepositoryType()
                .clickModalSubmit();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .expandSourceCodeFields()
                .setRepositoryURLEdited(repositoryURLEdited)
                .clickUpdateApplicationButtonInvalid();

        assertTrue("The correct error did not appear for the url field.",
                applicationDetailPage.getUrlRepositoryError().equals("URL is invalid."));
        assertFalse("Add Application Button is clickable",
                applicationDetailPage.isButtonEnabled());
    }

    @Test
    public void testSourceCodeValidation() {
        String teamName = createTeam();
        String appName = getName();

        String repositoryURL = "htt://test.com";

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName, appName, "http://testapp.com", "Low")
                .setRemoteSourceCodeURL(repositoryURL);

        assertTrue("The correct error did not appear for the url field.",
                teamIndexPage.getUrlRepositoryError().equals("URL is invalid."));
        assertFalse("Add Application Button is clickable",
                teamIndexPage.isAddApplicationButtonClickable());

    }

    @Test
    public void testSetSubversionRepository() {
        String teamName = createTeam();
        String appName = getName();

        String repositoryUrl = "https://github.com/spring-projects/spring-petclinic.git";

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName, appName, "http://testapp.com", "Low")
                .setRemoteSourceCodeURL(repositoryUrl)
                .selectSubversionRepositoryType()
                .clickModalSubmit();

        teamIndexPage.waitForClosedModal();

        assertFalse("The modal did not submit correctly using Subversion as source repo.",
                teamIndexPage.isAddApplicationButtonPresent());
    }

    //===========================================================================================================
    // Vulnerabilities
    //===========================================================================================================

    @Test
    public void testExpandCollapseVulnerability() {
        initializeTeamAndApp();
        String cwe = "Improper Validation of Certificate Expiration";
        String sourceFile = "/test";
        String parameter = "Test Parameter";
        String description = "Test Description.";
        String appVuln = "Critical298";
        String expandVuln = "expandVuln" + appVuln;
        String collapseVuln = "collapseVuln" + appVuln;

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .clickStaticRadioButton()
                .setCWE(cwe)
                .setSourceFile(sourceFile)
                .setParameter(parameter)
                .setSeverity("Critical")
                .setDescription(description)
                .clickDynamicSubmit();

        assertFalse("Manual Finding was not added.", applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage.refreshPage();

        applicationDetailPage.waitForResultsToLoad();

        applicationDetailPage.expandVulnerabilityByType(appVuln);
        sleep(2000);
        applicationDetailPage.collapseVulnerabilityByType(appVuln);
        sleep(2000);

        assertTrue("Vulnerability did not expand twice", applicationDetailPage.isClickable(expandVuln));

        applicationDetailPage.expandVulnerabilityByType(appVuln);
        sleep(2000);

        assertTrue("Vulnerability did not collapse twice", applicationDetailPage.isClickable(collapseVuln));
    }

    @Test
    public void testCommentValidation() {
        initializeTeamAndApp();
        String cwe = "Improper Validation of Certificate Expiration";
        String sourceFile = "/test";
        String parameter = "Test Parameter";
        String description = "Test Description.";
        String appVuln = "Critical298";
        String longComment = getRandomString(450);

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.clickActionButton()
                .clickManualFindingButton()
                .clickStaticRadioButton()
                .setCWE(cwe)
                .setSourceFile(sourceFile)
                .setParameter(parameter)
                .setSeverity("Critical")
                .setDescription(description)
                .clickDynamicSubmit();

        assertFalse("Manual Finding was not added.", applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage.refreshPage();

        applicationDetailPage.waitForResultsToLoad();

        applicationDetailPage.expandVulnerabilityByType(appVuln)
                .expandCommentSection(appVuln + "0")
                .addComment(appVuln + "0")
                .setComment("")
                .clickDynamicSubmit();

        assertTrue("Blank comment accepted as valid submission", applicationDetailPage.errorMessagePresent());

        applicationDetailPage.setComment(longComment);

        assertTrue(">200 character comment accepted", !applicationDetailPage.isButtonEnabled());
    }

    //===========================================================================================================
    // Other
    //===========================================================================================================

    @Test
    public void testUnmappedFindingsLink() {
        initializeTeamAndApp();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Unmapped Scan"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        FindingDetailPage findingDetailPage = applicationDetailPage.clickUnmappedFindings("20 Unmapped Findings")
                .clickUnmappedViewFinding();

        assertTrue("Finding Detail Page is not valid", findingDetailPage.isScannerVulnerabilityTextPresent());
    }

    @Test
    public void testUnmappedFindingsScan() {
        initializeTeamAndApp();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Unmapped Scan"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickUnmappedFindings("20 Unmapped Findings");

        assertTrue("Unmapped findings displayed does not match scan.", applicationDetailPage.checkNumberOfUnmappedCorrect(21));
    }

    @Test
    public void testUniqueId() {
        String teamName = createTeam();
        String appName = getName();

        String uniqueId = getName();

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName, appName, "http://testapp.com", "Low")
                .setUniqueId(uniqueId)
                .clickModalSubmit();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn();

        assertTrue("Unique ID wasn't saved", applicationDetailPage.isUniqueIdAvailabe(uniqueId));
    }

    @Test
    public void testTeamsAreSortedAlphabeticallyInDropdown() {
        String firstTeamName = "A" + getName();
        String appName = getName();

        DatabaseUtils.createTeam(firstTeamName);
        DatabaseUtils.createApplication(firstTeamName, appName);

        String secondTeamName = "Z" + getName();

        DatabaseUtils.createTeam(secondTeamName);

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(firstTeamName)
                .clickViewAppLink(appName, firstTeamName)
                .clickEditDeleteBtn()
                .clickTeamSelector();

        assertTrue("The teams weren't sorted in alphabetical order.",
                applicationDetailPage.compareOrderOfSelector(firstTeamName, secondTeamName));
    }

    //TODO wait till the bug for Scheduling to fix
    @Ignore
    @Test
    public void testDateRangeFilterSaving() {
        initializeTeamAndApp();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String filterName = "testFilter";
        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .expandDateRange()
                .enterStartDate("03-September-2014")
                .clickVulnerabilitiesTab(45);


        assertTrue("The Vulnerabilities still available", applicationDetailPage.areAllVulnerabilitiesHidden());

        applicationDetailPage.expandSavedFilters()
                .addSavedFilter(filterName)
                .clickLoadFilters()
                .loadSavedFilter(filterName);

        assertTrue("The Vulnerabilities still available", applicationDetailPage.areAllVulnerabilitiesHidden());
    }
}