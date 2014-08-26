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

import org.openqa.selenium.NoSuchElementException;

public class DashboardPage extends BasePage{

	public DashboardPage(WebDriver webdriver) {
		super(webdriver);
	}
	
	public boolean is6MonthGraphNoDataFound() {
        return "No data found".equals(driver.findElementById("leftTileReport")
                .findElement(By.className("report-image")).getText().trim());
	}
	
	public boolean isTop10GraphNoDataFound() {
        return "No data found".equals(driver.findElementById("rightTileReport")
                .findElement(By.className("report-image")).getText().trim());
    }

    public boolean isRecentUploadsNoScanFound() {
        return "No scans found.".equals(driver.findElementById("wafTableBody")
                .findElement(By.className("thick-left")).getText().trim());
    }

    public boolean isCommentDisplayed() {
        return driver.findElementById("viewMoreLink1").isDisplayed();
    }

    public boolean isAlertDisplayed() {
        try {
            return driver.findElementByClassName("alert-error").getText()
                    .contains("You don't have permission to access any ThreadFix applications or to create one for yourself.");
        } catch (NoSuchElementException e) {
            System.err.println("Alert was not displayed." + e.getMessage());
            return false;
        }
    }
	public AnalyticsPage clickLeftViewMore(){
		driver.findElementById("leftViewMore").click();
        waitForElement(driver.findElementById("csvLink"));
		return new AnalyticsPage(driver);
	}
	
	public AnalyticsPage clickRightViewMore(){
		driver.findElementById("rightViewMore").click();
        waitForElement(driver.findElementById("csvLink"));
		return new AnalyticsPage(driver);
	}
	
	public ApplicationDetailPage clickLatestUploadApp(){
		driver.findElementById("scanApplicationLink1").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
		
	public ScanDetailPage clickLatestUploadScan(){
		driver.findElementById("scanLink1").click();
		return new ScanDetailPage(driver);
	}
	
	public ApplicationDetailPage clickLatestCommentApp(){
		driver.findElementById("commentUser1").click();
		sleep(1000);
		return new ApplicationDetailPage(driver);
	}
	
	public VulnerabilityDetailPage clickLatestCommentLink(){
		driver.findElementsByLinkText("View").get(0).click();
		return new VulnerabilityDetailPage(driver);
	}
	
	public int getNumUploads(){
		return driver.findElementById("wafTableBody").findElements(By.className("bodyRow")).size();
	}
	
	public int getNumComments(){
		return driver.findElementsByClassName("bodyRow").size()-getNumUploads();
	}

    public boolean isLoggedin(){
        return driver.findElementsById("main-content").size() != 0;
    }
}
