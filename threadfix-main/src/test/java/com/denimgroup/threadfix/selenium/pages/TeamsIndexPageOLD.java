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

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class TeamsIndexPageOLD extends BasePage{
	private WebElement addTeamModalButton;
	private WebElement teamTable;
	private WebElement addAppModalButton;
	private List<WebElement> appLink = new ArrayList<>();
	private List<WebElement> appUploadLink = new ArrayList<>();
	
	public TeamsIndexPageOLD(WebDriver webdriver) {
		super(webdriver);
		teamTable = driver.findElementById("teamTable");
		addTeamModalButton = driver.findElementById("addTeamModalButton");
		addAppModalButton = driver.findElementById("addApplicationModalButton2");
		
		for (int i = 1; i <= getNumEdit(); i++) {
			appUploadLink.add(driver.findElementById("uploadScan" + i));
			appLink.add(driver.findElementById("applicationLink" + i));
		}
	}
	
	public TeamsIndexPageOLD clickAddTeamButton() {
		addTeamModalButton.click();
		return this;
	}
	
	public TeamsIndexPageOLD clickAddAppButton() {
		addAppModalButton.click();
		return this;	
	}
	
	public boolean isTeamNamePresent(String organizationName) {
	
		for (WebElement element : teamTable.findElements(By.xpath(".//tr/td/a"))) {
			if (element.getText().contains(organizationName)) {
				return true;
			}
		}
		return false;
	}

	public TeamsIndexPageOLD clickUpload(int Row) {
		appUploadLink.get(Row).click();
		sleep(1000);
		return this;
	}
	
	public int getNumEdit() {
		return driver.findElementsByLinkText("Configure").size();
	}
}
