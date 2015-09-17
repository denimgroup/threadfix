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
import com.denimgroup.threadfix.selenium.pages.PolicyPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamAppCustomizeVulnerabilityTypesPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class PolicyEntIT extends BaseDataTest {

    private PolicyPage initialize(String policyName) {
        String filterName = getName();

        return loginPage.defaultLogin()
                .clickPoliciesLink()
                .createGenericFilter(filterName)
                .createPolicy(policyName, filterName);
    }

    //================================================================================================
    // UI tests
    //================================================================================================

    @Test
    public void testCreatePolicy() {
        String policyName = getName();
        String filterName = getName();
        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createGenericFilter(filterName)
                .createPolicy(policyName, filterName);

        assertTrue("Policy is not present.", policyPage.isPolicyPresent(policyName));
        assertTrue("Policy name is not correct.", policyPage.isPolicyNameCorrect(policyName));
        assertTrue("Policy filter name is not correct.", policyPage.isPolicyFilterCorrect(policyName, filterName));
        assertTrue("Default policy status is not correct.", policyPage.isPolicyPassing(policyName));
    }

    @Test
    public void testDeletePolicy() {
        String name = getName();
        PolicyPage policyPage = initialize(name);

        assertTrue("Policy is not present.", policyPage.isPolicyPresent(name));

        policyPage.clickEditDeleteButton(name)
                .deletePolicy();

        assertFalse("Policy is still present after deletion.", policyPage.isPolicyPresent(name));
    }

    @Test
    public void testEditPolicy() {
        String policyName = getName();
        String editedPolicyName = getName();
        String newFilter = getName();
        PolicyPage policyPage = initialize(policyName)
                .createGenericFilter(newFilter);

        assertTrue("Policy is not present.", policyPage.isPolicyPresent(policyName));

        policyPage.clickEditDeleteButton(policyName)
                .setPolicyName(editedPolicyName)
                .setFilterForPolicy(newFilter)
                .savePolicy();

        assertTrue("Policy does not display edited name.", policyPage.isPolicyNameCorrect(editedPolicyName));
        assertTrue("Policy filter name is not the new filter.", policyPage.isPolicyFilterCorrect(editedPolicyName, newFilter));

        policyPage.clickEditDeleteButton(editedPolicyName)
                .setPolicyName(policyName)
                .savePolicy();

        assertTrue("Policy name could not be edited without changing filter.", policyPage.isPolicyNameCorrect(policyName));
        assertTrue("Policy filter name was changed.", policyPage.isPolicyFilterCorrect(policyName, newFilter));
    }

    @Test
    public void testAddAppToPolicy() {
        initializeTeamAndApp();
        String name = getName();
        PolicyPage policyPage = initialize(name);

        policyPage.expandPolicy(name)
                .addAppToPolicy(name, appName);

        assertTrue("Application was not added.", policyPage.isAppPresent(name, appName));
    }

    @Test
    public void testRemoveAppFromPolicy() {
        initializeTeamAndApp();
        String name = getName();
        PolicyPage policyPage = initialize(name);

        policyPage.expandPolicy(name)
                .addAppToPolicy(name, appName);

        assertTrue("Application was not added.", policyPage.isAppPresent(name, appName));

        policyPage.removeAppFromPolicy(name, appName);

        assertFalse("Application was not removed.", policyPage.isAppPresent(name, appName));
    }

    @Test
    public void testAddPolicyToApp() {
        initializeTeamAndApp();
        String name = getName();
        PolicyPage policyPage = initialize(name);

        ApplicationDetailPage applicationDetailPage = policyPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickEditDeleteBtn()
                .clickManagePolicy()
                .selectPolicy(name);

        assertTrue("Policy is not present in application modal.", applicationDetailPage.isPolicyInModal(appName, name));

        policyPage = applicationDetailPage.clickCloseModalButton()
                .clickPoliciesLink()
                .expandPolicy(name);

        assertTrue("Application is not present on acceptance policy page.", policyPage.isAppPresent(name, appName));
    }

    @Test
    public void testRemovePolicyFromApp() {
        initializeTeamAndApp();
        String name = getName();
        PolicyPage policyPage = initialize(name)
                .expandPolicy(name)
                .addAppToPolicy(name, appName);

        ApplicationDetailPage applicationDetailPage = policyPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickEditDeleteBtn()
                .clickManagePolicy()
                .removePolicy(name);

        assertFalse("Policy is still present in application modal.", applicationDetailPage.isPolicyInModal(appName, name));

        policyPage = applicationDetailPage.clickCloseModalButton()
                .clickPoliciesLink()
                .expandPolicy(name);

        assertFalse("Application is still present on acceptance policy page.", policyPage.isAppPresent(name, appName));
    }

    @Test
    public void testAddEmailsButtonForPolicy() {
        String name = getName();
        String email = getEmailAddress();
        String listName = getName();
        PolicyPage policyPage = initialize(name);

        policyPage.clickManageEmailListsLink()
                .clickCreateEmailList()
                .setEmailListName(listName)
                .clickSaveEmailList()
                .clickPoliciesLink()
                .clickAddEmailsButton(name)
                .addEmailAddress(email)
                .addEmailList(listName);

        assertTrue("Email was not added to policy.", policyPage.isEmailPresent(email));
        assertTrue("Email List was not added to policy.", policyPage.isEmailListPresent(listName));
    }

    @Test
    public void testAddEmailsButtonForApp() {
        initializeTeamAndApp();
        String name = getName();
        String email = getEmailAddress();
        String listName = getName();
        PolicyPage policyPage = initialize(name);

        policyPage.clickManageEmailListsLink()
                .clickCreateEmailList()
                .setEmailListName(listName)
                .clickSaveEmailList()
                .clickPoliciesLink()
                .expandPolicy(name)
                .addAppToPolicy(name, appName)
                .clickAddEmailsButtonForApp(appName, name)
                .addEmailAddress(email)
                .addEmailList(listName);

        assertTrue("Email was not added to app.", policyPage.isEmailPresent(email));
        assertTrue("Email List was not added to app.", policyPage.isEmailListPresent(listName));
    }

    //================================================================================================
    // Validation Tests
    //================================================================================================

    @Test
    public void testCreatePolicyValidation() {
        String filterName = getName();
        String secondFilterName = getName();
        String whitespace = "        ";
        String longName = getRandomString(51);
        String duplicateName = getName();
        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createGenericFilter(filterName)
                .createGenericFilter(secondFilterName)
                .clickCreatePolicy()
                .setPolicyName(duplicateName);

        assertTrue("Policy could be created with no Filter set.", policyPage.isSubmitDisabled());

        policyPage.setFilterForPolicy(filterName)
                .setPolicyName(whitespace);

        assertTrue("Policy could be created with empty name.", policyPage.isSubmitDisabled());
        assertTrue("Name required error is not displayed.", policyPage.isNameRequiredErrorDisplayed());

        policyPage.setPolicyName(longName);

        assertTrue("Policy could be created with long name.", policyPage.isSubmitDisabled());
        assertTrue("Name required error is not displayed.", policyPage.isLengthErrorDisplayed());

        policyPage.setPolicyName(duplicateName)
                .savePolicy()
                .clickCreatePolicy()
                .setPolicyName(duplicateName)
                .setFilterForPolicy(secondFilterName);

        assertFalse("Duplicate Policy name could be submitted.",
                policyPage.canSaveDuplicatePolicy());
    }

    @Test
    public void testEditPolicyValidation() {
        String filterName = getName();
        String secondFilterName = getName();
        String whitespace = "        ";
        String longName = getRandomString(51);
        String name = getName();
        String duplicateName = getName();
        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createGenericFilter(filterName)
                .createGenericFilter(secondFilterName)
                .createPolicy(duplicateName, filterName)
                .createPolicy(name, secondFilterName)
                .clickEditDeleteButton(name)
                .setPolicyName(whitespace);

        assertTrue("Policy could be edited to have empty name.", policyPage.isSubmitDisabled());
        assertTrue("Name required error is not displayed.", policyPage.isNameRequiredErrorDisplayed());

        policyPage.setPolicyName(longName);

        assertTrue("Policy could be edited to have long name.", policyPage.isSubmitDisabled());
        assertTrue("Name required error is not displayed.", policyPage.isLengthErrorDisplayed());

        policyPage.setPolicyName(duplicateName);

        assertFalse("Duplicate Policy name could be submitted by editing.",
                policyPage.canSaveDuplicatePolicy());
    }

    @Test
    public void testAddEmailsButtonValidationForPolicy() {
        String name = getName();
        String validEmail = getEmailAddress();
        String invalidEmail = "@";
        String invalidCharEmail = "asdf)@asdf.asdf";
        String longEmail = getRandomString(100) + "@" + getRandomString(100);
        String listName = getName();

        PolicyPage policyPage = initialize(name)
                .clickManageEmailListsLink()
                .clickCreateEmailList()
                .setEmailListName(listName)
                .clickSaveEmailList()
                .clickPoliciesLink()
                .clickAddEmailsButton(name)
                .addEmailAddress(invalidEmail);

        assertFalse("Invalid email was added to policy.", policyPage.isEmailPresent(invalidEmail));

        policyPage.addEmailAddress(invalidCharEmail);

        assertFalse("Email with invalid characters was added to policy.", policyPage.isEmailPresent(invalidCharEmail));

        policyPage.addEmailAddress(longEmail);

        assertFalse("Email with invalid length was added to policy.", policyPage.isEmailPresent(longEmail));

        policyPage.addEmailAddress(validEmail)
                .addEmailAddress(validEmail);

        assertTrue("Duplicate email was added to policy.", policyPage.getEmailError().contains("Email address already exists."));

        policyPage.addEmailList(listName)
                .addEmailList(listName);

        assertTrue("Duplicate email list was added to policy.", policyPage.getEmailListError().contains("Email list already added."));
    }

    @Test
    public void testAddEmailsButtonValidationForApp() {
        initializeTeamAndApp();
        String name = getName();
        String validEmail = getEmailAddress();
        String invalidEmail = "@";
        String invalidCharEmail = "asdf)@asdf.asdf";
        String longEmail = getRandomString(100) + "@" + getRandomString(100);
        String listName = getName();

        PolicyPage policyPage = initialize(name)
                .clickManageEmailListsLink()
                .clickCreateEmailList()
                .setEmailListName(listName)
                .clickSaveEmailList()
                .clickPoliciesLink()
                .expandPolicy(name)
                .addAppToPolicy(name, appName)
                .clickAddEmailsButtonForApp(appName, name);

        assertFalse("Invalid email was added to app.", policyPage.isEmailPresent(invalidEmail));

        policyPage.addEmailAddress(invalidCharEmail);

        assertFalse("Email with invalid characters was added to app.", policyPage.isEmailPresent(invalidCharEmail));

        policyPage.addEmailAddress(longEmail);

        assertFalse("Email with invalid length was added to app.", policyPage.isEmailPresent(longEmail));

        policyPage.addEmailAddress(validEmail)
                .addEmailAddress(validEmail);

        assertTrue("Duplicate email was added to app.", policyPage.getEmailError().contains("Email address already exists."));

        policyPage.addEmailList(listName)
                .addEmailList(listName);

        assertTrue("Duplicate email list was added to app.", policyPage.getEmailListError().contains("Email list already added."));
    }

    //================================================================================================
    // Functionality Tests
    //================================================================================================

    @Test
    public void testPassFailForNumberMerged() {
        String team = createTeam();
        String appFail = createApplication(team);
        uploadScanToApp(team, appFail, "New ZAP Scan");
        String appPass = createApplication(team);
        uploadScanToApp(team, appPass, "w3af");

        String policyName = getName();
        String filterName = getName();

        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createNumberMergedFilter(filterName)
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing.", policyPage.isAppPassing(appPass));
    }

    @Test
    public void testPassFailForScanner() {
        String team = createTeam();
        String appFail = createApplication(team);
        uploadScanToApp(team, appFail, "w3af");
        String appPass = createApplication(team);
        uploadScanToApp(team, appPass, "Fortify 360");

        String policyName = getName();
        String filterName = getName();

        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createScannerFilter(filterName, "w3af")
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing.", policyPage.isAppPassing(appPass));
    }

    @Test
    public void testPassFailForVulnerabilityType() {
        String team = createTeam();
        String appFail = createApplication(team);
        uploadScanToApp(team, appFail, "WebInspect");
        String appPass = createApplication(team);
        uploadScanToApp(team, appPass, "NTO Spider");

        String policyName = getName();
        String filterName = getName();

        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createVulnerabilityFilter(filterName, "79")
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing.", policyPage.isAppPassing(appPass));
    }

    @Test
    public void testPassFailForPath() {
        String team = createTeam();
        String appFail = createApplication(team);
        uploadScanToApp(team, appFail, "w3af");
        String appPass = createApplication(team);
        uploadScanToApp(team, appPass, "Fortify OrAndOr");

        String policyName = getName();
        String filterName = getName();

        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createPathFilter(filterName, "/demo/SQLI2.php")
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing.", policyPage.isAppPassing(appPass));
    }

    @Test
    public void testPassFailForParameter() {
        String team = createTeam();
        String appFail = createApplication(team);
        uploadScanToApp(team, appFail, "IBM Rational AppScan");
        String appPass = createApplication(team);
        uploadScanToApp(team, appPass, "Fortify OrAndOr");

        String policyName = getName();
        String filterName = getName();

        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createParameterFilter(filterName, "command")
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing.", policyPage.isAppPassing(appPass));
    }

    @Test
    public void testPassFailForSeverity() {
        String team = createTeam();
        String appFail = createApplication(team);
        uploadScanToApp(team, appFail, "Nessus");
        String appPass = createApplication(team);
        uploadScanToApp(team, appPass, "IBM Rational AppScan");

        String policyName = getName();
        String filterName = getName();

        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createGenericFilter(filterName)
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing critical filter.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing critical filter.", policyPage.isAppPassing(appPass));

        policyPage.clickFiltersTab()
                .selectFilterToEdit(filterName)
                .clickFieldControl("Critical")
                .clickFieldControl("High")
                .clickSaveFilterButton()
                .clickPolicyTab()
                .expandPolicy(policyName);

        assertTrue("Application should be passing high filter.", policyPage.isAppPassing(appFail));
        assertFalse("Application should be failing high filter.", policyPage.isAppPassing(appPass));
    }

    @Test
    public void testPassFailForOpenClosed() {
        String team = createTeam();
        String appFail = createApplication(team);
        DatabaseUtils.addManualFindingToApp(team, appFail);
        String appPass = createApplication(team);
        DatabaseUtils.addManualFindingToApp(team, appPass);

        String policyName = getName();
        String filterName = getName();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(team)
                .clickApplicationName(team, appPass)
                .expandVulnerabilityByType("Medium1")
                .checkVulnerabilityByType("Medium10")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton();

        PolicyPage policyPage = applicationDetailPage.clickPoliciesLink()
                .createOpenFilter(filterName)
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing open filter.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing open filter.", policyPage.isAppPassing(appPass));

        policyPage.clickFiltersTab()
                .selectFilterToEdit(filterName)
                .clickFieldControl("Open")
                .clickFieldControl("Closed")
                .clickSaveFilterButton()
                .clickPolicyTab()
                .expandPolicy(policyName);

        assertTrue("Application should be passing closed filter.", policyPage.isAppPassing(appFail));
        assertFalse("Application should be failing closed filter.", policyPage.isAppPassing(appPass));
    }

    @Test
    public void testPassFailForFalsePositive() {
        String team = createTeam();
        String appFail = createApplication(team);
        DatabaseUtils.addManualFindingToApp(team, appFail);
        String appPass = createApplication(team);
        DatabaseUtils.addManualFindingToApp(team, appPass);

        String policyName = getName();
        String filterName = getName();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(team)
                .clickApplicationName(team, appFail)
                .expandVulnerabilityByType("Medium1")
                .checkVulnerabilityByType("Medium10")
                .clickVulnerabilitiesActionButton()
                .clickMarkFalseVulnerability();

        PolicyPage policyPage = applicationDetailPage.clickPoliciesLink()
                .createFalsePositiveFilter(filterName)
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing.", policyPage.isAppPassing(appPass));
    }

    @Test
    public void testPassFailForHidden() {
        String team = createTeam();
        String appFail = createApplication(team);
        DatabaseUtils.addManualFindingToApp(team, appFail);
        String appPass = createApplication(team);
        DatabaseUtils.addManualFindingToApp(team, appPass);

        String policyName = getName();
        String filterName = getName();

        TeamAppCustomizeVulnerabilityTypesPage appCustomizeVulnerabilityTypesPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(team)
                .clickApplicationName(team, appFail)
                .clickActionButton()
                .clickEditVulnerabilityFilters()
                .enableSeverityFilters()
                .hideMedium()
                .saveFilterChanges();

        PolicyPage policyPage = appCustomizeVulnerabilityTypesPage.clickPoliciesLink()
                .createHiddenFilter(filterName)
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing.", policyPage.isAppPassing(appPass));
    }

    @Test
    public void testPassFailForAging() {
        String team = createTeam();
        String appFail = createApplication(team);
        uploadScanToApp(team, appFail, "IBM Rational AppScan");
        String appPass = createApplication(team);
        uploadScanToApp(team, appPass, "AppScanEnterprise");

        String policyName = getName();
        String filterName = getName();

        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createAgingFilter(filterName)
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing less than filter.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing less than filter.", policyPage.isAppPassing(appPass));

        policyPage.clickFiltersTab()
                .selectFilterToEdit(filterName)
                .clickMoreThan()
                .clickSaveFilterButton()
                .clickPolicyTab()
                .expandPolicy(policyName);

        assertTrue("Application should be passing more than filter.", policyPage.isAppPassing(appFail));
        assertFalse("Application should be failing more than filter.", policyPage.isAppPassing(appPass));
    }

    @Ignore("Date Range filter doesn't respond to Selenium")
    @Test
    public void testPassFailForDateRange() {
        String team = createTeam();
        String appFail = createApplication(team);
        uploadScanToApp(team, appFail, "IBM Rational AppScan");
        String appPass = createApplication(team);
        uploadScanToApp(team, appPass, "AppScanEnterprise");

        String policyName = getName();
        String filterName = getName();

        PolicyPage policyPage = loginPage.defaultLogin()
                .clickPoliciesLink()
                .createDateRangeFilter(filterName)
                .createPolicy(policyName, filterName)
                .expandPolicy(policyName)
                .addAppToPolicy(policyName, appFail)
                .addAppToPolicy(policyName, appPass);

        assertFalse("Application should be failing more than filter.", policyPage.isAppPassing(appFail));
        assertTrue("Application should be passing more than filter.", policyPage.isAppPassing(appPass));
    }
}
