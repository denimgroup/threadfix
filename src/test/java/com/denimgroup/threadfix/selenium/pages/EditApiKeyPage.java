////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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

public class EditApiKeyPage extends BasePage {

	private WebElement notes;
	private WebElement restrictedCheckBox;
	private WebElement updateButton;
	private WebElement backToListLink;

	public EditApiKeyPage(WebDriver webdriver) {
		super(webdriver);
		notes = driver.findElementById("note");
		restrictedCheckBox = driver.findElementById("isRestrictedKey1");
		updateButton = driver.findElementById("updateApiKeyButton");
		backToListLink = driver.findElementByLinkText("Back to API Key");
	}

	public EditApiKeyPage setNoteStatus(String status) {
		notes.clear();
		notes.sendKeys(status);
		return this;
	}

	public EditApiKeyPage clickUpdate() {
		updateButton.click();
		sleep(1000);
		return this;
	}

	public EditApiKeyPage clickBackToListLink() {
		backToListLink.click();
		sleep(1000);
		return this;
	}

	public void setRestrictCheckBoxValue(Boolean isRestChkBox) {

		if (getRestrictedCheckBox().isSelected() && !isRestChkBox)

			getRestrictedCheckBox().click();

		else if (!getRestrictedCheckBox().isSelected() && isRestChkBox)

			getRestrictedCheckBox().click();

	}

	public void setRestrictCheckBox(WebElement restrictedBox) {
		restrictedCheckBox = restrictedBox;
	}

	public WebElement getRestrictedCheckBox() {
		return restrictedCheckBox;
	}

	public ApiKeysIndexPage fillAllClickSave(String notesField, boolean restrictedBox) {
		fillRequired(notesField, restrictedBox);
		setNoteStatus(notesField);
		setRestrictCheckBoxValue(restrictedBox);
		updateButton.click();
		return new ApiKeysIndexPage(driver);
	}

	public EditApiKeyPage fillRequired(String notesField, boolean restrictedBox) {
		setNoteStatus(notesField);
		setRestrictCheckBoxValue(restrictedBox);
		return this;
	}


}
