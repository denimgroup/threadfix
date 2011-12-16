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

public class ApplicationDetailPage extends BasePage {

	private WebElement editLink;
	private WebElement deleteLink;
	private WebElement viewScansLink;
	private WebElement uploadScanLink;
	private WebElement importSentinelLink;
	private WebElement addFindingManuallyLink;
	private WebElement viewPathLink;
	private WebElement viewSurfaceStructureLink;
	private WebElement viewCodeStructureLink;
	private WebElement markFalsePositivesLink;
	private WebElement unmarkMarkedFalsePositivesLink;
	private WebElement nameText;
	private WebElement urlText;
	private WebElement organizationText;
	
	public ApplicationDetailPage(WebDriver webdriver) {
		super(webdriver);
		
		editLink = driver.findElementById("editLink");
		deleteLink = driver.findElementById("deleteLink");
		viewScansLink = driver.findElementById("viewScansLink");
		uploadScanLink = driver.findElementById("uploadScanLink");
		importSentinelLink = driver.findElementById("importSentinelLink");
		addFindingManuallyLink = driver.findElementById("addFindingManuallyLink");
		viewPathLink = driver.findElementById("viewPathLink");
		viewSurfaceStructureLink = driver.findElementById("viewSurfaceStructureLink");
		viewCodeStructureLink = driver.findElementById("viewCodeStructureLink");
		markFalsePositivesLink = driver.findElementById("markFalsePositivesLink");
		unmarkMarkedFalsePositivesLink = driver.findElementById("unmarkMarkedFalsePositivesLink");
		nameText = driver.findElementById("nameText");
		urlText = driver.findElementById("urlText");
		organizationText = driver.findElementById("organizationText");
	}
	
	public String getWafText(){
		return driver.findElementById("wafText").getText();
	}
	
	public String getNameText(){
		return nameText.getText();
	}
	
	public String getUrlText(){
		return urlText.getText();
	}
	
	public String getDefectTrackerText() {
		return driver.findElementById("defectTrackerText").getText();
	}
	
	public String getOrganizationText(){
		return organizationText.getText();
	}
	
	public ApplicationEditPage clickEditLink() {
		editLink.click();
		return new ApplicationEditPage(driver);
	}

	public OrganizationDetailPage clickDeleteLink() {
		deleteLink.click();
		
		Alert alert = driver.switchTo().alert();
		alert.accept();
		
		return new OrganizationDetailPage(driver);
	}

	public OrganizationIndexPage clickViewScansLink() {
		viewScansLink.click();
		return new OrganizationIndexPage(driver);
	}

	public UploadScanPage clickUploadScanLink() {
		uploadScanLink.click();
		return new UploadScanPage(driver);
	}
	
	public AddChannelPage clickUploadScanLinkFirstTime() {
		uploadScanLink.click();
		return new AddChannelPage(driver);
	}

	public OrganizationIndexPage clickImportSentinelLink() {
		importSentinelLink.click();
		return new OrganizationIndexPage(driver);
	}

	public OrganizationIndexPage clickAddFindingManuallyLink() {
		addFindingManuallyLink.click();
		return new OrganizationIndexPage(driver);
	}

	public OrganizationIndexPage clickViewPathLink() {
		viewPathLink.click();
		return new OrganizationIndexPage(driver);
	}

	public OrganizationIndexPage clickViewSurfaceStructureLink() {
		viewSurfaceStructureLink.click();
		return new OrganizationIndexPage(driver);
	}

	public OrganizationIndexPage clickViewCodeStructureLink() {
		viewCodeStructureLink.click();
		return new OrganizationIndexPage(driver);
	}

	public OrganizationIndexPage clickMarkFalsePositivesLink() {
		markFalsePositivesLink.click();
		return new OrganizationIndexPage(driver);
	}

	public OrganizationIndexPage clickUnmarkMarkedFalsePositivesLink() {
		unmarkMarkedFalsePositivesLink.click();
		return new OrganizationIndexPage(driver);
	}

}
