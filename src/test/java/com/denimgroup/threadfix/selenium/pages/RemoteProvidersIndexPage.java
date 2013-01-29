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

import org.openqa.selenium.Alert;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class RemoteProvidersIndexPage extends BasePage {
	private List<WebElement> name = new ArrayList<WebElement>();
	private List<WebElement> userName = new ArrayList<WebElement>();
	private List<WebElement> apiKey = new ArrayList<WebElement>();
	private List<WebElement> configureButton = new ArrayList<WebElement>();

	private List<WebElement> appName = new ArrayList<WebElement>();
	private List<WebElement> appTeam = new ArrayList<WebElement>();
	private List<WebElement> appApplication = new ArrayList<WebElement>();
	private List<WebElement> appEditLink = new ArrayList<WebElement>();
	private List<WebElement> appImportScanLinks = new ArrayList<WebElement>();
	private List<WebElement> updateAppsLink = new ArrayList<WebElement>();
	private List<WebElement> clearConfig = new ArrayList<WebElement>();

	public RemoteProvidersIndexPage(WebDriver webDriver) {
		super(webDriver);

		for (int i = 1; i <= getNumEdit(); i++) {
			name.add(driver.findElementById("name" + i));
			userName.add(driver.findElementById("username" + i));
			apiKey.add(driver.findElementById("apiKey" + i));
			configureButton.add(driver.findElementById("configure" + i));
			
			if (!driver.findElementById("username"+i).getText().equals("")
					|| !driver.findElementById("apiKey"+i).getText().equals("")) {
				
				updateAppsLink.add(driver.findElementById("updateApps"+i));
				clearConfig.add(driver.findElementById("clearConfig"+i));
				for (int j = 1; j <= getNumRows(); j++) {
					
					appName.add(driver.findElementById("provider" + i + "appid" + j));
					appTeam.add(driver.findElementById("provider" + i + "tfteamname"
							+ j));
					appApplication.add(driver.findElementById("provider" + i + "tfappname" + j));
					appEditLink.add(driver.findElementById("provider" + i + "updateMapping" + j));

					if (driver.findElementById("provider" + i + "tfteamname" + j)
							.getText().equals("")) {

					} else
						appImportScanLinks.add(driver
								.findElementById("provider" + i + "import" + j));

				}
			}
		}
	}

	public int getNumEdit() {
		return driver.findElementsByLinkText("Configure").size();

	}

	public int getNumRows() {
		return driver.findElementsByLinkText("Edit Mapping").size();
	}

	public String getNames(int num) {
		return name.get(num).getText();

	}

	public String getUsernames(int num) {
		return userName.get(num).getText();

	}

	public String getAPIKey(int num) {
		return apiKey.get(num).getText();

	}

	public RemoteProviderCredentialsPage clickConfigure(int Row) {
		configureButton.get(Row).click();
		sleep(1000);
		return new RemoteProviderCredentialsPage(driver);
	}

	public EditMappingPage clickEdit(int Row) {
		appEditLink.get(Row).click();
		sleep(1000);
		return new EditMappingPage(driver);
	}

	public void clickImport(int Row) {
		appImportScanLinks.get(Row).click();
		sleep(1000);
	}

	public void clickUpdate(int Row) {
		//UpdateAppsLink = driver.findElementById("updateApps1");
		updateAppsLink.get(Row).click();
		sleep(1000);
	}

	public RemoteProvidersIndexPage clickClearConfigButton(int rowNumber) {
		clearConfig.get(rowNumber).click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new RemoteProvidersIndexPage(driver);
	}

}