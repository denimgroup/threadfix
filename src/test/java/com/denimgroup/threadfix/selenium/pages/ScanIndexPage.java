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

import java.util.List;

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class ScanIndexPage extends BasePage {

	private WebElement scanTable;
	private WebElement backToApplicationLink;

	public ScanIndexPage(WebDriver webdriver) {
		super(webdriver);
		scanTable = driver.findElementById("wafTableBody");
		backToApplicationLink = driver.findElementById("backToApplicationLink");
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
}
