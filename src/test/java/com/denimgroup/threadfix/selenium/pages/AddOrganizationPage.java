////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

public class AddOrganizationPage extends BasePage {

	private WebElement nameInput;
	private WebElement submitButton;
	
	public AddOrganizationPage(WebDriver webdriver) {
		super(webdriver);
		nameInput = driver.findElementById("nameInput");
		submitButton = driver.findElementById("submitButton");
	}
	
	public String getErrorText(){
		return driver.findElementById("name.errors").getText();
	}
	
	public String getNameInput(){
		return nameInput.getText();
	}

	public AddOrganizationPage setNameInput(String text){
		nameInput.clear();
		nameInput.sendKeys(text);
		return this;
	}

	public OrganizationDetailPage clickSubmitButtonValid() {
		submitButton.click();
		return new OrganizationDetailPage(driver);
	}
	
	public AddOrganizationPage clickSubmitButtonInvalid() {
		submitButton.click();
		return new AddOrganizationPage(driver);
	}

}
