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

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class ReportsIndexPage extends BasePage {
	private Select teamSelect;
	private Select applicationSelect;
	private Select reportSelect;
	private Select formatSelect;
	private WebElement runReportButton;
	
	public ReportsIndexPage(WebDriver webdriver) {
		super(webdriver);
	}
	
	public String selectTeamList(String text) {
		teamSelect = new Select(driver.findElementById("orgSelect"));
		teamSelect.selectByVisibleText(text);
		return teamSelect.getFirstSelectedOption().getText();
	}

	public String selectApplicationList(String text) {
		applicationSelect = new Select(driver.findElementById("appSelect"));
		applicationSelect.selectByVisibleText(text);
		return applicationSelect.getFirstSelectedOption().getText();
	}
	
	public String selectReportList(String text) {
		reportSelect = new Select(driver.findElementById("reportId"));
		reportSelect.selectByVisibleText(text);
		return reportSelect.getFirstSelectedOption().getText();
	}
	
	public String selectFormatList(String text) {
		formatSelect = new Select(driver.findElementById("formatId"));
		formatSelect.selectByVisibleText(text);
		return formatSelect.getFirstSelectedOption().getText();
	}
	
	public void clickRunRpt() {
		runReportButton = driver.findElementById("runReportButton");
		runReportButton.click();
		sleep(1000);
	}

	public GeneratedReportPage fillAllClickSaveReport(String reportSelect,String teamSelect, String ApplicationSelect,String formatSelect) {
		fillRequiredReport(reportSelect,teamSelect, ApplicationSelect,formatSelect);
		selectReportList(reportSelect);
		selectTeamList(teamSelect);
		selectApplicationList(ApplicationSelect);
		selectFormatList(formatSelect);
		runReportButton.click();
		sleep(1000);
		return new GeneratedReportPage(driver);
	}

	public GeneratedReportPage fillRequiredReport(String reportSelect,String teamSelect, String ApplicationSelect,String formatSelect) {
		selectReportList(reportSelect);
		selectTeamList(teamSelect);
		selectApplicationList(ApplicationSelect);
		selectFormatList(formatSelect);
		sleep(1000);
		return new GeneratedReportPage(driver);
	}
}
