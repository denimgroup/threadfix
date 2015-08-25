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
import com.denimgroup.threadfix.selenium.pages.AcceptancePolicyPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class AcceptancePolicyEntIT extends BaseDataTest {

    private AcceptancePolicyPage initialize(String policyName) {
        String filterName = getName();

        return loginPage.defaultLogin()
                .clickAcceptancePoliciesLink()
                .createGenericFilter(filterName)
                .createAcceptancePolicy(policyName, filterName);
    }

    //================================================================================================
    // UI tests
    //================================================================================================

    @Test
    public void testCreateAcceptancePolicy() {
        String policyName = getName();
        String filterName = getName();
        AcceptancePolicyPage acceptancePolicyPage = loginPage.defaultLogin()
                .clickAcceptancePoliciesLink()
                .createGenericFilter(filterName)
                .createAcceptancePolicy(policyName, filterName);

        assertTrue("Acceptance Policy is not present.", acceptancePolicyPage.isPolicyPresent(policyName));
        assertTrue("Policy name is not correct.", acceptancePolicyPage.isPolicyNameCorrect(policyName));
        assertTrue("Policy filter name is not correct.", acceptancePolicyPage.isPolicyFilterCorrect(policyName, filterName));
        assertTrue("Default policy status is not correct.", acceptancePolicyPage.isPolicyPassing(policyName));
    }

    @Test
    public void testDeleteAcceptancePolicy() {
        String name = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(name);

        assertTrue("Acceptance Policy is not present.", acceptancePolicyPage.isPolicyPresent(name));

        acceptancePolicyPage.clickEditDeleteButton(name)
                .deletePolicy();

        assertFalse("Acceptance Policy is still present after deletion.", acceptancePolicyPage.isPolicyPresent(name));
    }

    @Test
    public void testEditAcceptancePolicy() {
        String policyName = getName();
        String editedPolicyName = getName();
        String newFilter = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(policyName)
                .createGenericFilter(newFilter);

        assertTrue("Acceptance Policy is not present.", acceptancePolicyPage.isPolicyPresent(policyName));

        acceptancePolicyPage.clickEditDeleteButton(policyName)
                .setAcceptancePolicyName(editedPolicyName)
                .setFilterForPolicy(newFilter)
                .saveAcceptancePolicy();

        assertTrue("Acceptance Policy does not display edited name.", acceptancePolicyPage.isPolicyNameCorrect(editedPolicyName));
        assertTrue("Policy filter name is not the new filter.", acceptancePolicyPage.isPolicyFilterCorrect(editedPolicyName, newFilter));

        acceptancePolicyPage.clickEditDeleteButton(editedPolicyName)
                .setAcceptancePolicyName(policyName)
                .saveAcceptancePolicy();

        assertTrue("Acceptance Policy name could not be edited without changing filter.", acceptancePolicyPage.isPolicyNameCorrect(policyName));
        assertTrue("Policy filter name was changed.", acceptancePolicyPage.isPolicyFilterCorrect(policyName, newFilter));
    }

    @Test
    public void testAddAppToAcceptancePolicy() {
        initializeTeamAndApp();
        String name = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(name);

        acceptancePolicyPage.expandAcceptancePolicy(name)
                .addAppToAcceptancePolicy(name, appName);

        assertTrue("Application was not added.", acceptancePolicyPage.isAppPresent(name, appName));
    }

    @Test
    public void testRemoveAppFromAcceptancePolicy() {
        initializeTeamAndApp();
        String name = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(name);

        acceptancePolicyPage.expandAcceptancePolicy(name)
                .addAppToAcceptancePolicy(name, appName);

        assertTrue("Application was not added.", acceptancePolicyPage.isAppPresent(name, appName));

        acceptancePolicyPage.removeAppFromPolicy(name, appName);

        assertFalse("Application was not removed.", acceptancePolicyPage.isAppPresent(name, appName));
    }

    @Test
    public void testAddAcceptancePolicyToApp() {
        initializeTeamAndApp();
        String name = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(name);

        ApplicationDetailPage applicationDetailPage = acceptancePolicyPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickEditDeleteBtn()
                .clickManageAcceptancePolicy()
                .addAcceptancePolicy(name);

        assertTrue("Acceptance Policy is not present in application modal.", applicationDetailPage.isAccetpancePolicyInModal(appName, name));

        acceptancePolicyPage = applicationDetailPage.clickCloseModalButton()
                .clickAcceptancePoliciesLink()
                .expandAcceptancePolicy(name);

        assertTrue("Application is not present on acceptance policy page.", acceptancePolicyPage.isAppPresent(name, appName));
    }

    @Test
    public void testRemoveAcceptancePolicyFromApp() {
        initializeTeamAndApp();
        String name = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(name)
                .expandAcceptancePolicy(name)
                .addAppToAcceptancePolicy(name, appName);

        ApplicationDetailPage applicationDetailPage = acceptancePolicyPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickEditDeleteBtn()
                .clickManageAcceptancePolicy()
                .removeAcceptancePolicy(name);

        assertFalse("Acceptance Policy is still present in application modal.", applicationDetailPage.isAccetpancePolicyInModal(appName, name));

        acceptancePolicyPage = applicationDetailPage.clickCloseModalButton()
                .clickAcceptancePoliciesLink()
                .expandAcceptancePolicy(name);

        assertFalse("Application is still present on acceptance policy page.", acceptancePolicyPage.isAppPresent(name, appName));
    }

    @Ignore("Awaiting ID changes")
    @Test
    public void testAddEmailsButtonForPolicy() {
        String name = getName();
        String email = getEmailAddress();
        String listName = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(name);

        acceptancePolicyPage.clickManageEmailListsLink()
                .clickCreateEmailList()
                .setEmailListName(listName)
                .clickSaveEmailList()
                .clickAcceptancePoliciesLink()
                .clickAddEmailsButton(name)
                .addEmailAddress(email)
                .addEmailList(listName);

        assertTrue("Email was not added to acceptance policy.", acceptancePolicyPage.isEmailPresent(email));
        assertTrue("Email List was not added to acceptance policy.", acceptancePolicyPage.isEmailListPresent(listName));
    }

    @Ignore("Awaiting ID changes")
    @Test
    public void testAddEmailsButtonForApp() {
        initializeTeamAndApp();
        String name = getName();
        String email = getEmailAddress();
        String listName = getName();
        AcceptancePolicyPage acceptancePolicyPage = initialize(name);

        acceptancePolicyPage.clickManageEmailListsLink()
                .clickCreateEmailList()
                .setEmailListName(listName)
                .clickSaveEmailList()
                .clickAcceptancePoliciesLink()
                .expandAcceptancePolicy(name)
                .addAppToAcceptancePolicy(name, appName)
                .clickAddEmailsButtonForApp(appName, name)
                .addEmailAddress(email)
                .addEmailList(listName);

        assertTrue("Email was not added to app.", acceptancePolicyPage.isEmailPresent(email));
        assertTrue("Email List was not added to app.", acceptancePolicyPage.isEmailListPresent(listName));
    }

    //================================================================================================
    // Validation Tests
    //================================================================================================

    @Test
    public void testCreateAcceptancePolicyValidation() {
        String filterName = getName();
        String secondFilterName = getName();
        String whitespace = "        ";
        String longName = getRandomString(51);
        String duplicateName = getName();
        AcceptancePolicyPage acceptancePolicyPage = loginPage.defaultLogin()
                .clickAcceptancePoliciesLink()
                .createGenericFilter(filterName)
                .createGenericFilter(secondFilterName)
                .clickCreateAcceptancePolicy()
                .setAcceptancePolicyName(duplicateName);

        assertTrue("Acceptance Policy could be created with no Filter set.", acceptancePolicyPage.isSubmitDisabled());

        acceptancePolicyPage.setFilterForPolicy(filterName)
                .setAcceptancePolicyName(whitespace);

        assertTrue("Acceptance Policy could be created with empty name.", acceptancePolicyPage.isSubmitDisabled());
        assertTrue("Name required error is not displayed.", acceptancePolicyPage.isNameRequiredErrorDisplayed());

        acceptancePolicyPage.setAcceptancePolicyName(longName);

        assertTrue("Acceptance Policy could be created with long name.", acceptancePolicyPage.isSubmitDisabled());
        assertTrue("Name required error is not displayed.", acceptancePolicyPage.isLengthErrorDisplayed());

        acceptancePolicyPage.setAcceptancePolicyName(duplicateName)
                .saveAcceptancePolicy()
                .clickCreateAcceptancePolicy()
                .setAcceptancePolicyName(duplicateName)
                .setFilterForPolicy(secondFilterName);

        assertFalse("Duplicate Acceptance Policy name could be submitted.",
                acceptancePolicyPage.canSaveDuplicateAcceptancePolicy());
    }

    @Test
    public void testEditAcceptancePolicyValidation() {
        String filterName = getName();
        String secondFilterName = getName();
        String whitespace = "        ";
        String longName = getRandomString(51);
        String name = getName();
        String duplicateName = getName();
        AcceptancePolicyPage acceptancePolicyPage = loginPage.defaultLogin()
                .clickAcceptancePoliciesLink()
                .createGenericFilter(filterName)
                .createGenericFilter(secondFilterName)
                .createAcceptancePolicy(duplicateName, filterName)
                .createAcceptancePolicy(name, secondFilterName)
                .clickEditDeleteButton(name)
                .setAcceptancePolicyName(whitespace);

        assertTrue("Acceptance Policy could be edited to have empty name.", acceptancePolicyPage.isSubmitDisabled());
        assertTrue("Name required error is not displayed.", acceptancePolicyPage.isNameRequiredErrorDisplayed());

        acceptancePolicyPage.setAcceptancePolicyName(longName);

        assertTrue("Acceptance Policy could be edited to have long name.", acceptancePolicyPage.isSubmitDisabled());
        assertTrue("Name required error is not displayed.", acceptancePolicyPage.isLengthErrorDisplayed());

        acceptancePolicyPage.setAcceptancePolicyName(duplicateName);

        assertFalse("Duplicate Acceptance Policy name could be submitted by editing.",
                acceptancePolicyPage.canSaveDuplicateAcceptancePolicy());
    }
}
