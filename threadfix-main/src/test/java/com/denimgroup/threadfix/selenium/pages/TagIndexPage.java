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
package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class TagIndexPage extends BasePage{

    public TagIndexPage(WebDriver webDriver) {
        super(webDriver);
    }

    /*------------------------------ Action Methods ------------------------------*/

    public TagIndexPage createNewTag(String name) {
        driver.findElementById("createTagModalButton").click();
        driver.findElementById("tagCreateNameInput").sendKeys(name);
        clickModalSubmit();
        return new TagIndexPage(driver);
    }

    public TagIndexPage deleteTag(String name) {
        driver.findElementById("editTagModalButton" + name).click();
        driver.findElementById("deleteTagButton").click();
        driver.switchTo().alert().accept();
        sleep(1000);
        return new TagIndexPage(driver);
    }

    public TagIndexPage editTagName(String tagName, String newName) {
        driver.findElementById("editTagModalButton" + tagName).click();
        waitForElement(driver.findElementById("tagCreateNameInput"));
        driver.findElementById("tagCreateNameInput").clear();
        driver.findElementById("tagCreateNameInput").sendKeys(newName);
        clickModalSubmit();
        sleep(1000);
        return new TagIndexPage(driver);
    }

    public TagDetailPage clickTagName(String name) {
        driver.findElementByLinkText(name).click();
        waitForElement(driver.findElementByLinkText("Back to Tags Page"));
        return new TagDetailPage(driver);
    }

    /*------------------------------ Boolean Methods ------------------------------*/

    public boolean isTagNameLinkPresent(String name) { return !driver.findElements(By.id("tagName" + name)).isEmpty(); }
}
