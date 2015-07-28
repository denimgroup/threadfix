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

import com.denimgroup.threadfix.selenium.pages.EmailListPage;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class EmailListIT extends BaseDataTest {

    public EmailListPage initialize(String listName) {
        return loginPage.defaultLogin()
                .clickManageEmailListsLink()
                .clickCreateEmailList()
                .setEmailListName(listName)
                .clickSaveEmailList();
    }

    public String getEmailAddress() {
        return getRandomString(8) + "@denimgroup.com";
    }

    @Test
    public void testCreateEmailList() {
        String name = getName();

        EmailListPage emailListPage = initialize(name);

        assertTrue("Email List is not present", emailListPage.isEmailListPresent(name));
        assertTrue("Success message is incorrect",
                emailListPage.getSuccessMessage().contains("Successfully created email list " + name));
    }

    @Test
    public void testEditEmailList() {
        String startName = getName();
        String endName = getName();

        EmailListPage emailListPage = initialize(startName);
        assertTrue("Email List is not present", emailListPage.isEmailListPresent(startName));

        emailListPage.clickEditEmailList(startName)
                .setEmailListName(endName)
                .clickSaveEmailList();

        assertTrue("Email List was not edited correctly", emailListPage.isEmailListPresent(endName));
        assertTrue("Success message is incorrect",
                emailListPage.getSuccessMessage().contains("Successfully edited email list " + startName));
    }

    @Test
    public void testDeleteEmailList() {
        String name = getName();

        EmailListPage emailListPage = initialize(name);
        assertTrue("Email List is not present", emailListPage.isEmailListPresent(name));

        emailListPage.clickEditEmailList(name)
                .clickDeleteEmailList();

        assertFalse("Email List was not deleted", emailListPage.isEmailListPresent(name));
        assertTrue("Success message is incorrect",
                emailListPage.getSuccessMessage().contains("The deletion was successful for email list " + name));
    }

    @Test
    public void testAddEmailToEmailList() {
        String listName = getName();
        String addressName = getEmailAddress();

        EmailListPage emailListPage = initialize(listName);
        assertTrue("Email List is not present", emailListPage.isEmailListPresent(listName));

        emailListPage.clickShowHideButton(listName)
                .addEmailAddress(listName, addressName);

        assertTrue("Email Address was not added to list", emailListPage.isEmailAddressPresent(listName, 0));
    }

    @Test
    public void testDeleteEmailFromEmailList() {
        String listName = getName();
        String addressName = getEmailAddress();

        EmailListPage emailListPage = initialize(listName);
        assertTrue("Email List is not present", emailListPage.isEmailListPresent(listName));

        emailListPage.clickShowHideButton(listName)
                .addEmailAddress(listName, addressName);

        assertTrue("Email Address was not added to list", emailListPage.isEmailAddressPresent(listName, 0));

        emailListPage.deleteEmailAddress(listName, 0);

        assertFalse("Email Address was not deleted from list", emailListPage.isEmailAddressPresent(listName, 0));
    }

    @Test
    public void testEmailListValidation() {
        String name = getName();
        String emptyName = "          ";
        String longName = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        EmailListPage emailListPage = initialize(name);
        assertTrue("Email List is not present", emailListPage.isEmailListPresent(name));

        emailListPage.clickCreateEmailList()
                .setEmailListName(emptyName)
                .clickSaveEmailList();

        assertTrue("Name is required error is not present", emailListPage.isEmailListEmptyErrorPresent());

        emailListPage.setEmailListName(longName)
                .clickSaveEmailList();

        assertTrue("Character limit error is not present", emailListPage.isEmailListLengthErrorPresent());

        emailListPage.setEmailListName(name)
                .clickSaveEmailList();

        assertTrue("Duplicate name error is not present", emailListPage.isEmailListDuplicateErrorPresent());
    }

    @Test
    public void testEmailListAddressValidation() {
        String listName = getName();
        String addressName = getEmailAddress();

        EmailListPage emailListPage = initialize(listName);
        assertTrue("Email List is not present", emailListPage.isEmailListPresent(listName));

        emailListPage.clickShowHideButton(listName)
                .addEmailAddress(listName, addressName);

        assertTrue("Email Address was not added to list", emailListPage.isEmailAddressPresent(listName, 0));

        emailListPage.addEmailAddress(listName, addressName);

        assertFalse("Duplicate Email Address was allowed", emailListPage.isEmailAddressPresent(listName, 1));

        emailListPage.addEmailAddress(listName, listName);

        assertFalse("Invalid Email Address was allowed", emailListPage.isEmailAddressPresent(listName, 1));
    }
}
