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

import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

public class TagIndexPage extends BasePage{

    public TagIndexPage(WebDriver webDriver) {
        super(webDriver);
    }

    /*------------------------------ Action Methods ------------------------------*/

    public TagIndexPage createNewTag(String name) {
        driver.findElementById("createTagModalButton").click();
        waitForElement(By.id("myModalLabel"));
        driver.findElementById("tagCreateNameInput").sendKeys(name);
        clickModalSubmit();
        return new TagIndexPage(driver);
    }

    public TagIndexPage createNewCommentTag(String name) {
        driver.findElementById("createTagModalButton").click();
        waitForElement(By.id("myModalLabel"));
        driver.findElementById("tagCreateNameInput").sendKeys(name);
        new Select(driver.findElementById("tagType")).selectByVisibleText("COMMENT");
        clickModalSubmit();
        waitForElementPresenceByCss("div.alert.alert-success:not(.ng-hide)", 5);
        return new TagIndexPage(driver);
    }

    public TagIndexPage deleteTag(String name) {
        driver.findElementById("editTagModalButton" + name).click();
        waitForElement(By.id("deleteTagButton"));
        driver.findElementById("deleteTagButton").click();
        driver.switchTo().alert().accept();
        sleep(1000);
        return new TagIndexPage(driver);
    }

    public TagIndexPage deleteCommentTag(String name) {
        driver.findElementById("editCommentTagModalButton" + name).click();
        waitForElement(By.id("deleteTagButton"));
        driver.findElementById("deleteTagButton").click();
        driver.switchTo().alert().accept();
        sleep(1000);
        return new TagIndexPage(driver);
    }

    public TagIndexPage editTagName(String tagName, String newName) {
        driver.findElementById("editTagModalButton" + tagName).click();
        waitForElement(By.id("tagCreateNameInput"));
        driver.findElementById("tagCreateNameInput").clear();
        driver.findElementById("tagCreateNameInput").sendKeys(newName);
        driver.findElementById("submit").click();
        sleep(10000);
        return new TagIndexPage(driver);
    }

    public TagIndexPage editCommentTagName(String tagName, String newName) {
        driver.findElementById("editCommentTagModalButton" + tagName).click();
        waitForElement(By.id("tagCreateNameInput"));
        driver.findElementById("tagCreateNameInput").clear();
        driver.findElementById("tagCreateNameInput").sendKeys(newName);
        driver.findElementById("submit").click();
        sleep(10000);
        return new TagIndexPage(driver);
    }

    public TagDetailPage clickTagName(String name) {
        driver.findElementByLinkText(name).click();
        waitForElement(By.linkText("Back to Tags Page"));
        return new TagDetailPage(driver);
    }

    /*------------------------------ Boolean Methods ------------------------------*/

    public boolean isAppTagNameLinkPresent(String name) {
        try {
            waitForElement(By.id("tagName" + name));
        } catch (TimeoutException e) {
            return false;
        }
        return true;
    }

    public boolean isCommentTagNameLinkPresent(String name) {
        try {
            waitForElement(By.id("commentTagName" + name));
        } catch (TimeoutException e) {
            return false;
        }
        return true;
    }

    public boolean isVulnerabilityTagNameLinkPresent(String name) {
        try {
            waitForElement(By.id("vulnTagName" + name));
        } catch (TimeoutException e) {
            return false;
        }
        return true;
    }
}
