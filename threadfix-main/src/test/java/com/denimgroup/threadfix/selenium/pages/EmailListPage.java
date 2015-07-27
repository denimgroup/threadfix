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

package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;

public class EmailListPage extends BasePage {

    public EmailListPage(WebDriver webDriver) { super(webDriver); }

    /*------------------------------------ Utility Methods ------------------------------------*/

    public EmailListPage clickCreateEmailList() {
        driver.findElementById("createEmailListModalButton").click();
        waitForElement(driver.findElementById("submit"));
        return new EmailListPage(driver);
    }

    public EmailListPage setEmailListName(String listName) {
        driver.findElementById("emailListCreateNameInput").clear();
        driver.findElementById("emailListCreateNameInput").sendKeys(listName);
        return this;
    }

    public EmailListPage clickSaveEmailList() {
        driver.findElementById("submit").click();
        return new EmailListPage(driver);
    }

    public EmailListPage clickEditEmailList(String listName) {
        driver.findElementById("editEmailListModalButton" + listName).click();
        waitForElement(driver.findElementById("submit"));
        return new EmailListPage(driver);
    }

    public EmailListPage clickDeleteEmailList() {
        driver.findElementById("deleteEmailListButton").click();
        handleAlert();
        return new EmailListPage(driver);
    }

    /*------------------------------------ Boolean Methods ------------------------------------*/

    public boolean isEmailListPresent(String listName){
        try {
            driver.findElementById("emailListName" + listName);
        } catch(NoSuchElementException e) {
            return false;
        }
        return true;
    }

    /*------------------------------------ Getter Methods ------------------------------------*/

    public String getSuccessMessage() {
        return driver.findElementByCssSelector("div.alert-success:not(.ng-hide)").getText();
    }

}
