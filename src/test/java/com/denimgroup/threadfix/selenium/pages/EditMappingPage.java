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
import org.openqa.selenium.support.ui.Select;

public class EditMappingPage extends BasePage {
	private Select team;
	private Select application;
	private WebElement updateButton;
	private WebElement backToRemoteLink;

	public EditMappingPage(WebDriver webDriver) {
		super(webDriver);
		team = new Select(driver.findElementById("orgSelect"));
		application = new Select(driver.findElementById("appSelect"));
		updateButton = driver.findElementById("submitButton");
		backToRemoteLink = driver.findElementById("backToIndexLink");

	}

	public EditMappingPage selectTeamList(String text) {
		team.selectByVisibleText(text);
		return this;
	}

	public EditMappingPage selectAppList(String text) {
		application.selectByVisibleText(text);
		return this;
	}

	public RemoteProvidersIndexPage clickUpdate() {
		updateButton.click();
		return new RemoteProvidersIndexPage(driver);
	}

	public RemoteProvidersIndexPage clickBackLink() {
		backToRemoteLink.click();
		return new RemoteProvidersIndexPage(driver);
	}

	public RemoteProvidersIndexPage fillAllClickSaveTeam(String team, String Application) {
		fillRequired(team, Application);
		// selectteamList(team);
		// selectAppList(Application);
		updateButton.click();
		return new RemoteProvidersIndexPage(driver);
	}

	public void fillRequired(String team, String Application) {
		selectTeamList(team);
		selectAppList(Application);
	}
}
