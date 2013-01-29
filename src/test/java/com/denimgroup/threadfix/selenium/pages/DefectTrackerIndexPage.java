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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class DefectTrackerIndexPage extends BasePage { 

	private WebElement defectTrackerTableBody;
	private WebElement lastItemFoundInDefectTrackerTableBodyLink;
	private WebElement addDefectTrackerLink;
	
	public static final String DT_URL = "http://10.2.10.145/bugzilla/";

	public DefectTrackerIndexPage(WebDriver webdriver) {
		super(webdriver);
		defectTrackerTableBody = driver.findElementById("defectTrackerTableBody");
		addDefectTrackerLink = driver.findElementById("addDefectTrackerLink");

	}

	public boolean isTextPresentInDefectTrackerTableBody(String text) {
		for (WebElement element : defectTrackerTableBody.findElements(By.xpath(".//tr/td/a"))) {
			if (element.getText().contains(text)) {
				lastItemFoundInDefectTrackerTableBodyLink = element;
				return true;
			}
		}
		return false;
	}

	public DefectTrackerDetailPage clickTextLinkInDefectTrackerTableBody(String text) {
		if (isTextPresentInDefectTrackerTableBody(text)) {
			lastItemFoundInDefectTrackerTableBodyLink.click();
			return new DefectTrackerDetailPage(driver);
		} else {
			return null;
		}
	}

	public DefectTrackerAddPage clickAddDefectTrackerLink() {
		addDefectTrackerLink.click();
		return new DefectTrackerAddPage(driver);
	}

}