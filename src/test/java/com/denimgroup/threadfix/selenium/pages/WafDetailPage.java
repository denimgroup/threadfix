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
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class WafDetailPage extends BasePage {

	private WebElement nameText;
	private WebElement wafTypeText;
	private WebElement editLink;
	private WebElement backToListLink;
	private WebElement generateWafRulesButton;
	private WebElement downloadWafRulesButton;
	private WebElement applicationsTableBody;
	private WebElement lastItemFoundInApplicationsTableBodyLink;
	private WebElement deleteButton;
	private Select wafDirectiveSelect;
	
	public WafDetailPage(WebDriver webdriver) {
		super(webdriver);
		
		nameText = driver.findElementById("nameText");
		wafTypeText = driver.findElementById("wafTypeText");
		editLink = driver.findElementById("editLink");
		backToListLink = driver.findElementById("backToListLink");
		generateWafRulesButton = driver.findElementById("generateWafRulesButton");
		downloadWafRulesButton = driver.findElementById("downloadWafRulesButton");
		applicationsTableBody = driver.findElementById("applicationsTableBody");
		deleteButton = driver.findElementById("deleteButton");
		wafDirectiveSelect = new Select(driver.findElementById("wafDirectiveSelect"));
	}

	public String getNameText(){
		return nameText.getText();
	}

	public String getWafTypeText(){
		return wafTypeText.getText();
	}

	public WafEditPage clickEditLink() {
		editLink.click();
		return new WafEditPage(driver);
	}

	public WafIndexPage clickBackToListLink() {
		backToListLink.click();
		return new WafIndexPage(driver);
	}

	public OrganizationIndexPage clickGenerateWafRulesButton() {
		generateWafRulesButton.click();
		return new OrganizationIndexPage(driver);
	}

	public OrganizationIndexPage clickDownloadWafRulesButton() {
		downloadWafRulesButton.click();
		return new OrganizationIndexPage(driver);
	}

	public boolean isTextPresentInApplicationsTableBody(String text) {
		for (WebElement element : applicationsTableBody.findElements(By.xpath(".//tr/td/a"))) {
			if (element.getText().contains(text)) {
				lastItemFoundInApplicationsTableBodyLink = element;
				return true;
			}
		}
		return false;
	}

	public ApplicationDetailPage clickTextLinkInApplicationsTableBody(String text) {
		if (isTextPresentInApplicationsTableBody(text)) {
			lastItemFoundInApplicationsTableBodyLink.click();
			return new ApplicationDetailPage(driver);
		} else {
			return null;
		}
	}

	public WafIndexPage clickDeleteButton() {
		deleteButton.click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new WafIndexPage(driver);
	}
	
	public WafDetailPage clickDeleteButtonInvalid() {
		deleteButton.click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new WafDetailPage(driver);
	}

	public String getWafDirectiveSelect(){
		return wafDirectiveSelect.getFirstSelectedOption().getText();
	}

	public void setWafDirectiveSelect(String code){
		wafDirectiveSelect.selectByVisibleText(code);
	}
	
}
