////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
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

import org.openqa.selenium.Alert;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class UserDetailPage extends BasePage {

	private WebElement editLink;
	private WebElement deleteLink;
	private WebElement backToListLink;
	private WebElement nameText;
	private WebElement roleText;
	
	public UserDetailPage(WebDriver webdriver) {
		super(webdriver);

		editLink = driver.findElementById("editLink");
		deleteLink = driver.findElementById("deleteLink");
		backToListLink = driver.findElementById("backToListLink");
		nameText = driver.findElementById("nameText");
		roleText = driver.findElementById("roleText");

	}

	public UserEditPage clickEditLink() {
		editLink.click();
		return new UserEditPage(driver);
	}

	public UserIndexPage clickDeleteLink() {
		deleteLink.click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new UserIndexPage(driver);
	}
	
	public LoginPage clickDeleteLinkSameUser() {
		deleteLink.click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new LoginPage(driver);
	}

	public UserIndexPage clickBackToListLink() {
		backToListLink.click();
		return new UserIndexPage(driver);
	}
	
	public String getNameText(){
		return nameText.getText();
	}
	
	public String getRoleText(){
		return roleText.getText();
	}
	
}
