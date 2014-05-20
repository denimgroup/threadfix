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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

public class ScanDetailPage extends BasePage{

	public ScanDetailPage(WebDriver webdriver) {
		super(webdriver);

	}
	
	public String getScanHeader(){
		return getH2Tag().trim();
	}
	
	public int getNumOfFindings(){
		int cnt = 0;
		cnt += getNumofErrorFindings();
		cnt += getNumofWarningFindings();
		cnt += getNumofSuccessFindings();
		cnt += getNumofInfoFindings();
		return cnt;
	}
	
	public int getNumofErrorFindings(){
		return driver.findElementsByClassName("error").size();
	}
	
	public int getNumofWarningFindings(){
		return driver.findElementsByClassName("warning").size();
	}
	
	public int getNumofSuccessFindings(){
		return driver.findElementsByClassName("success").size();
	}
	
	public int getNumofInfoFindings(){
		return driver.findElementsByClassName("info").size();
	}
	
	public int getNumofUnmappedFindings(){
		int cnt = driver.findElementsById("1").get(1).findElements(By.className("bodyRow")).size();
		if(cnt == 1 && 
				driver.findElementsById("1").get(1).findElement(By.className("bodyRow"))
				.getText().contains("All Findings were mapped to vulnerabilities.")){
			cnt = 0;
		}
		return cnt;
	}
	
	public int getNumofMappedFindings(){
		return driver.findElementsById("1").get(0).findElements(By.className("bodyRow")).size();
	}
	//TODO add method to click specific finding link
	
	public String getSeverity(int row){
		return driver.findElementById("mappedSeverity"+row).getText();
	}
	
	public String getVulnType(int row){
		return driver.findElementById("mappedSeverity"+row).getText();
	}
	public String getPath(int row){
		return driver.findElementById("mappedSeverity"+row).getText();
	}
	public String getParameter(int row){
		return driver.findElementById("mappedSeverity"+row).getText();
	}
	public String getNumMergedResults(int row){
		return driver.findElementById("mappedSeverity"+row).getText();
	}
	public FindingDetailPage clickViewFinding(){
		driver.findElementById("mappedVulnType").click();
        waitForElement(driver.findElementByLinkText("View Vulnerability"));
		return new FindingDetailPage(driver);
	}
	
}
