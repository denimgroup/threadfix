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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.ArrayList;
import java.util.List;

public class ApiKeysIndexPage extends BasePage {
	private List<WebElement> notes = new ArrayList<>();
	private WebElement createNewKeyLink;


    /* _____________________ Action Methods _____________________ */
	public ApiKeysIndexPage(WebDriver webdriver) {
		super(webdriver);
		createNewKeyLink = driver.findElementById("createNewKeyModalButton");
	}

	public ApiKeysIndexPage clickEdit(String note) {
		driver.findElementById("editKeyModal" + note).click();
		return new ApiKeysIndexPage(driver);
	}

	public ApiKeysIndexPage clickNewLink() {
		createNewKeyLink.click();
		waitForElement(driver.findElementById("submit"));
		return new ApiKeysIndexPage(driver);
	}

	public ApiKeysIndexPage clickDelete(String note) {
		clickEdit(note);
		driver.findElementById("deleteButton").click();
		handleAlert();
		sleep(1000);

		return new ApiKeysIndexPage(driver);
	}

    public ApiKeysIndexPage clickSubmitButton() {
        return clickModalSubmit();
    }

    public ApiKeysIndexPage clickInvalidSubmitButton() {
        driver.findElementById("submit").click();
        sleep(1000);
        return new ApiKeysIndexPage(driver);
    }

    public ApiKeysIndexPage setNote(String newNote){
        driver.findElementById("modalNote").clear();
        driver.findElementById("modalNote").sendKeys(newNote);
        return this;
    }

    public ApiKeysIndexPage setRestricted() {
        driver.findElementById("modalRestricted").click();
        return new ApiKeysIndexPage(driver);
    }

    /* _____________________ Boolean Methods _____________________ */
	public boolean isCreationSuccessAlertPresent(){
		return driver.findElementByClassName("alert-success").getText().contains("Successfully created key");
	}
	
	public boolean isEditSuccessAlertPresent(){
		return driver.findElementByClassName("alert-success").getText().contains("Successfully edited key");
	}
	
	public boolean isDeleteSuccessAlertPresent(){
		return driver.findElementByClassName("alert-success").getText().contains("API key was successfully deleted.");
	}

    public boolean isAPINotePresent(String note) {
        List<WebElement> elements  = driver.findElementsById("note" + note);
        return elements != null && elements.size() > 0;
    }
	
	public boolean isAPIRestricted(String note){
		return driver.findElementById("restricted" + note).getText().trim().contains("true");
	}
	
	public boolean isCorrectLength(String note){
		return driver.findElementById("note" + note).getText().trim().length()<=255;
	}

    /* _____________________ Get Methods _____________________ */
    public String getNoteError() {
        return driver.findElementById("lengthLimitError").getText();
    }
	
	public int getTableWidth(){
		return driver.findElementById("table").getSize().width;
	}
}
