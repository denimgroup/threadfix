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
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
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
                .addPolicy(name);

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

    @Ignore("Awaiting ID changes")
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

    @Ignore("Awaiting ID changes")
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
}
