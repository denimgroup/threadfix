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

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class UserIndexPage extends BasePage {
	
	private WebElement addUserLink;
	
	private List<WebElement> deleteButtons = new ArrayList<WebElement>();
	private List<WebElement> names = new ArrayList<WebElement>();
	private List<WebElement> editLinks = new ArrayList<WebElement>();

	public int getNumRows() {
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	public UserIndexPage(WebDriver webdriver) {
		super(webdriver);

		addUserLink = driver.findElementById("addUserLink");
		
		for (int i = 1; i <= getNumRows(); i++) {
			deleteButtons.add(driver.findElementById("delete" + i));
			names.add(driver.findElementById("name" + i));
			editLinks.add(driver.findElementById("edit" + i));
		}
	}
	
	private int getIndex(String roleName) {
		int i = -1;
		for (WebElement name : names) {
			i++;
			String text = name.getText().trim();
			if (text.equals(roleName.trim())) {
				return i;
			}
		}
		return -1;
	}
	
	public UserIndexPage clickDeleteButton(String roleName) {
		deleteButtons.get(getIndex(roleName)).click();
		handleAlert();
		return new UserIndexPage(driver);
	}
	
	public LoginPage clickDeleteButtonSameUser(String roleName) {
		deleteButtons.get(getIndex(roleName)).click();
		handleAlert();
		return new LoginPage(driver);
	}

	public UserNewPage clickAddUserLink() {
		addUserLink.click();
		return new UserNewPage(driver);
	}

	public boolean isUserNamePresent(String userName) {
		return getIndex(userName) != -1;
	}
	
	public UserEditPage clickEditLink(String roleName) {
		editLinks.get(getIndex(roleName)).click();
		return new UserEditPage(driver);
	}
}
