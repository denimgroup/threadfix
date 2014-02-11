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

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.List;

public class ScanIndexPage extends BasePage {

	private WebElement scanTable;
	private WebElement backToApplicationLink;

	public ScanIndexPage(WebDriver webdriver) {
		super(webdriver);
		scanTable = driver.findElementById("wafTableBody");
//		backToApplicationLink = driver.findElementById("backToApplicationLink");
	}

	public ScanIndexPage clickDeleteScanButton(int index) {

		List<WebElement> scanDeleteButtonArray = scanTable.findElements(By
				.id("deleteScanButton"));

		if (scanDeleteButtonArray.size() > index) {
			scanDeleteButtonArray.get(index).click();
			Alert alert = driver.switchTo().alert();
			alert.accept();
			return new ScanIndexPage(driver);
		}
		return null;
	}

	public ApplicationDetailPage clickBackToAppLink() {
		backToApplicationLink.click();
		return new ApplicationDetailPage(driver);
	}
	
	public int getNumScanRows(){
		int cnt = driver.findElementsByClassName("bodyRow").size();
		if(cnt == 1){
			if(driver.findElementByClassName("bodyRow").getText().contains("No scans found.")){
				return 0;
			}
		}
		return cnt;
	}
	
	public ApplicationDetailPage clickApplicationLink(String teamName,String appName,String Scanner){
		if(getNumScanRows()==0){
			return null;
		}
		for(int i=1;i<=getNumScanRows();i++){
			if(driver.findElementById("application"+i).getText().equals(appName) &&
					driver.findElementById("team"+i).equals(teamName) &&
					driver.findElementById("channelType"+i).equals(Scanner)){
				driver.findElementById("application"+i).click();
				break;
			}
		}
		return new ApplicationDetailPage(driver);
	}
	
	public TeamDetailPage clickTeamLink(String teamName,String appName,String Scanner){
		if(getNumScanRows()==0){
			return null;
		}
		for(int i=1;i<=getNumScanRows();i++){
			if(driver.findElementById("application"+i).getText().equals(appName) &&
					driver.findElementById("team"+i).equals(teamName) &&
					driver.findElementById("channelType"+i).equals(Scanner)){
				driver.findElementById("team"+i).click();
				break;
			}
		}
		return new TeamDetailPage(driver);
	}
	public ScanDetailPage clickAnyViewScanLink(){
		driver.findElementByLinkText("View Scan").click();
		return new ScanDetailPage(driver);
	}
	public ScanDetailPage clickViewScanLink(String teamName,String appName,String Scanner){
		if(getNumScanRows()==0){
			return null;
		}
		for(int i=1;i<=getNumScanRows();i++){
			if(driver.findElementById("application"+i).getText().equals(appName) &&
					driver.findElementById("team"+i).equals(teamName) &&
					driver.findElementById("channelType"+i).equals(Scanner)){
				driver.findElementsByLinkText("View Scan").get(i-1).click();
				break;
			}
		}
		return new ScanDetailPage(driver);
	}

	public int getTableWidth() {
		return driver.findElementById("toReplace").getSize().width;
	}
	
	
}
