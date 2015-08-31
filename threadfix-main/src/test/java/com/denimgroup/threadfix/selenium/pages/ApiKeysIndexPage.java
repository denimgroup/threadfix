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
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.List;

public class ApiKeysIndexPage extends BasePage {
	private WebElement createNewKeyLink = driver.findElementById("createNewKeyModalButton");

    public ApiKeysIndexPage(WebDriver webdriver) { super(webdriver); }

    //===========================================================================================================
    // Action Methods
    //===========================================================================================================

	public ApiKeysIndexPage clickEditDeleteButton(String note) {
		driver.findElementById("editKeyModal" + note).click();
		return new ApiKeysIndexPage(driver);
	}

	public ApiKeysIndexPage clickCreateNewKeyLink() {
		createNewKeyLink.click();
		waitForElement(By.id("submit"));
		return new ApiKeysIndexPage(driver);
	}

	public ApiKeysIndexPage deleteApiKey(String note) {
		clickEditDeleteButton(note);
		driver.findElementById("deleteButton").click();
		handleAlert();
		return new ApiKeysIndexPage(driver);
	}

    public ApiKeysIndexPage clickSubmitButton() {
        return clickModalSubmit();
    }

    public ApiKeysIndexPage clickSubmitButtonInvalid() {
        return clickModalSubmitInvalid();
    }

    //===========================================================================================================
    // Set Methods
    //===========================================================================================================

    public ApiKeysIndexPage setNote(String newNote){
        driver.findElementById("modalNote").clear();
        driver.findElementById("modalNote").sendKeys(newNote);
        return this;
    }

    public ApiKeysIndexPage setRestricted() {
        driver.findElementById("modalRestricted").click();
        return new ApiKeysIndexPage(driver);
    }

    //===========================================================================================================
    // Get Methods
    //===========================================================================================================

    public String getNoteError() {
        return driver.findElementById("lengthLimitError").getText();
    }

    public int getTableWidth() {
        return driver.findElementById("table").getSize().width;
    }

    //===========================================================================================================
    // Boolean Methods
    //===========================================================================================================

    public boolean isCreationSuccessAlertPresent(){
		return isSuccessAlertPresent("Successfully created key");
	}
	
	public boolean isEditSuccessAlertPresent(){
		return isSuccessAlertPresent("Successfully edited key");
	}
	
	public boolean isDeleteSuccessAlertPresent(){
		return isSuccessAlertPresent("API key was successfully deleted.");
	}

    public boolean isApiKeyNotePresent(String note) {
        List<WebElement> elements  = driver.findElementsById("note" + note);
        return elements != null && elements.size() > 0;
    }
	
	public boolean isApiKeyRestricted(String note){
		return driver.findElementById("restricted" + note).getText().trim().contains("true");
	}

    //===========================================================================================================
    // Helper Methods
    //===========================================================================================================

    private boolean isSuccessAlertPresent(String message) {
        return driver.findElementByClassName("alert-success").getText().contains(message);
    }

}
