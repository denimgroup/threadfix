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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class WafIndexPage extends BasePage {

	private WebElement addWafLink;
	private WebElement wafTableBody;
	private WebElement lastItemFoundInWafTableBodyLink;
	
	public WafIndexPage(WebDriver webdriver) {
		super(webdriver);
		
		addWafLink = driver.findElementById("addWafLink");
		wafTableBody = driver.findElementById("wafTableBody");
	}

	public WafAddPage clickAddWafLink() {
		addWafLink.click();
		return new WafAddPage(driver);
	}

	public boolean isTextPresentInWafTableBody(String text) {
		for (WebElement element : wafTableBody.findElements(By.xpath(".//tr/td/a"))) {
			if (element.getText().contains(text)) {
				lastItemFoundInWafTableBodyLink = element;
				return true;
			}
		}
		return false;
	}

	public WafDetailPage clickTextLinkInWafTableBody(String text) {
		if (isTextPresentInWafTableBody(text)) {
			lastItemFoundInWafTableBodyLink.click();
			return new WafDetailPage(driver);
		} else {
			return null;
		}
	}
	
}
