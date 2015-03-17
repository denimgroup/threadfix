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
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import javax.validation.constraints.AssertTrue;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class ApplicationIT extends BaseDataTest {

    @Test
    public void testCreateBasicApplicationDisplayedTeamIndexPage() {
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
    public void testCreateBasicApplicationDisplayedApplicationDetailPage() {
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
    public void testCreateBasicAppFromTeamDetailPage() {
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
    public void testCreateBasicApplicationDuplicateValidation() {
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
    public void testEditBasicApplicationDisplayedApplicationDetailPage() {
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
    public void testEditBasicApplicationDisplayedTeamIndexPage() {
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
    public void testEditBasicApplicationValidation() {
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
    public void sameAppNameMultipleTeams() {
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
    public void switchTeamTest() {
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

        Boolean isAppAttachedToTeam1 = teamDetailPage.isAppPresent(appName);

        teamDetailPage = teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName2);

        Boolean isAppAttachedToTeam2 = teamDetailPage.isAppPresent(appName);

        assertTrue("The application was not switched properly.", !isAppAttachedToTeam1 && isAppAttachedToTeam2);
    }

    /*___________________________ Manual Findings ___________________________*/
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
    public void testVulnExpandCollapse() {
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
                .setDescription(description)
                .clickDynamicSubmit();

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
                .setDescription(description)
                .clickDynamicSubmit();

        applicationDetailPage.expandVulnerabilityByType(appVuln)
                .expandCommentSection(appVuln + "0")
                .addComment(appVuln + "0")
                .setComment("")
                .clickDynamicSubmit();

        assertTrue("Blank comment accepted as valid submission", applicationDetailPage.errorMessagePresent());

        applicationDetailPage.setComment(longComment);

        assertTrue(">200 character comment accepted", !applicationDetailPage.isButtonEnabled());
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

    /*___________________________ Deletion ___________________________*/

    @Test
    public void deleteUploadedScan() {
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
    public void deleteApplicationTest() {
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
    public void remoteSourceCodeTest() {
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
    public void editSourceCodeTest() {
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
        String teamName = createTeam();
        String appName = getName();

        String repositoryPath = System.getProperty("sourceCodeLocation");

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName, appName, "http://testapp.com", "High")
                .setSourceCodeFolder(repositoryPath)
                .clickModalSubmit();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .expandSourceCodeFields();

        assertFalse("Repository Path was not saved properly",
                applicationDetailPage.isRepositoryPathEmpty());
    }

    @Test
    public void createAppSourceCodeValidate() {
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
    public void editApplicationSourceCodeValidation() {
        String teamName = createTeam();
        String appName = getName();

        String repositoryURL = "http://test.com";
        String repositoryURLEdited = "htp://test1.com";

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .addNewApplication(teamName, appName, "http://testapp.com", "Low")
                .setRemoteSourceCodeURL(repositoryURL)
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
    public void checkUnmappedFindingsLink() {
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
    public void uploadNewScan() {
        initializeTeamAndApp();

        String newScan = ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan");

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickActionButton()
                .clickUploadScan()
                .uploadScan(newScan);

        assertTrue("Scan didn't Upload", applicationDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
    }

    @Test
    public void uploadSameScanTwiceOnApplicationPage() {
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
    public void uniqueIDTest() {
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
    public void unmappedFindingScanTest() {
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
    public void AlphabetizeSortTeamByEditApplication() {
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

        assertTrue("The Teams wasn't not sorted",
                applicationDetailPage.compareOrderOfSelector(firstTeamName, secondTeamName));
    }

    //TODO wait till the bug for Scheduling to fix
    @Ignore
    @Test
    public void checkDateRangeFilterSaving() {
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

    @Test
    public void checkDependencyScanInformation() {
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
    public void cancelDeleteScanAlert() {
        initializeTeamAndApp();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScansTab()
                .cancelDeleteScanTaskButton();

        applicationDetailPage.clickDeleteScanButton();

        assertTrue("Delete Button is still available", applicationDetailPage.isScanDeleted());
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

    @Test
    public void testFortifySeverityFilterScans() {

        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Fortify AndOrAnd"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        assertTrue("There should be one critical vulnerability.", applicationDetailPage.isVulnerabilityCountCorrect("Critical", "1"));
        assertTrue("There should be seven high vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("High", "7"));
        assertTrue("There should be 24 low vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("Low", "24"));

        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Fortify OrAndOr"));

        applicationDetailPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        assertTrue("There should be one critical vulnerability.", applicationDetailPage.isVulnerabilityCountCorrect("Critical", "1"));
        assertTrue("There should be seven medium vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("Medium", "7"));
        assertTrue("There should be 24 low vulnerabilities.", applicationDetailPage.isVulnerabilityCountCorrect("Low", "24"));

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
}