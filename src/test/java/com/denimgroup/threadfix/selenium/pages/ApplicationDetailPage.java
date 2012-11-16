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

public class ApplicationDetailPage extends BasePage {
	
	public ApplicationDetailPage(WebDriver webdriver) {
		super(webdriver);
		sleep(300);
	}
	
	public String getElementText(String id) {
		return driver.findElementById(id).getText();
	}
	
	public ApplicationDetailPage clickRefreshLink() {
		driver.findElementById("refreshLink").click();
		return new ApplicationDetailPage(driver);
	}
	
	public VulnerabilityPage clickVulnLink(int indexFromOne) {
		driver.findElementById("vulnName" + indexFromOne).click();
		return new VulnerabilityPage(driver);
	}
	
	public String getWafText(){
		return driver.findElementById("wafText").getText();
	}
	
	public String getNameText(){
		return driver.findElementById("nameText").getText();
	}
	
	public String getUrlText(){
		return driver.findElementById("urlText").getText();
	}
	
	public String getDefectTrackerText() {
		return driver.findElementById("defectTrackerText").getText();
	}
	
	public String getOrganizationText(){
		return driver.findElementById("organizationText").getText();
	}
	
	public ApplicationEditPage clickEditLink() {
		driver.findElementById("editLink").click();
		return new ApplicationEditPage(driver);
	}
	
	public OrganizationDetailPage clickTeamLink() {
		driver.findElementById("organizationText").click();
		sleep(300);
		return new OrganizationDetailPage(driver);
	}

	public OrganizationDetailPage clickDeleteLink() {
		driver.findElementById("deleteLink").click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new OrganizationDetailPage(driver);
	}

	public ScanIndexPage clickViewScansLink() {
		driver.findElementById("viewScansLink").click();
		return new ScanIndexPage(driver);
	}

	public UploadScanPage clickUploadScanLink() {
		driver.findElementById("uploadScanLink").click();
		return new UploadScanPage(driver);
	}
	
	public AddChannelPage clickUploadScanLinkFirstTime() {
		driver.findElementById("uploadScanLink").click();
		return new AddChannelPage(driver);
	}

	public ManualUploadPage clickAddFindingManuallyLink() {
		driver.findElementById("addFindingManuallyLink").click();
		return new ManualUploadPage(driver);
	}
	
	public int getNumRows() {
		return driver.findElementsByClassName("bodyRow").size();
	}

	public ApplicationDetailPage waitForScans() {
		
		ApplicationDetailPage returnPage = this;
		
		String appName = getNameText();
		
		returnPage = returnPage.clickTeamLink().clickTextLinkInApplicationsTableBody(appName);
		
		while (!isElementPresent("viewScansLink")) {
			returnPage = returnPage.clickTeamLink().clickTextLinkInApplicationsTableBody(appName);
			sleep(2000);
		}
		return returnPage;
	}

}
