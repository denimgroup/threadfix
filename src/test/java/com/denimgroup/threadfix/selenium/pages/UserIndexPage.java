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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class UserIndexPage extends BasePage {
	
	private WebElement addUserLink;
	private WebElement userTable;
	
	private WebElement lastUserFoundInTableLink;

	public UserIndexPage(WebDriver webdriver) {
		super(webdriver);

		addUserLink = driver.findElementById("addUserLink");
		userTable = driver.findElementById("userTableBody");
	}

	public UserNewPage clickAddUserLink() {
		addUserLink.click();
		return new UserNewPage(driver);
	}
	
	public boolean isUserNamePresent(String userName) {
		
		for (WebElement element : userTable.findElements(By.xpath(".//tr/td/a"))) {
			if (element.getText().contains(userName)) {
				lastUserFoundInTableLink = element;
				return true;
			}
		}
		
		return false;
	}
	
	public UserDetailPage clickUserNameLink(String userName) {
		if (isUserNamePresent(userName)) {
			lastUserFoundInTableLink.click();
			return new UserDetailPage(driver);
		} else {
			return null;
		}
	}
}
