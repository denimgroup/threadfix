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

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class AddChannelPage extends BasePage { 

	private WebElement cancelButton;
	private WebElement addChannelButton;
	private Select channelTypeSelect;

	public AddChannelPage(WebDriver webdriver) {
		super(webdriver);
		cancelButton = driver.findElementById("cancelButton");
		addChannelButton = driver.findElementById("addChannelButton");
		channelTypeSelect = new Select(driver.findElementById("channelTypeSelect"));
	}

	public ApplicationDetailPage clickCancelButton() {
		cancelButton.click();
		return new ApplicationDetailPage(driver);
	}
	public UploadScanPage clickAddChannelButton() {
		addChannelButton.click();
		return new UploadScanPage(driver);
	}
	public String getChannelTypeSelect(){
		return channelTypeSelect.getFirstSelectedOption().getText();
	}

	public AddChannelPage setChannelTypeSelect(String code){
		channelTypeSelect.selectByVisibleText(code);
		return this;
	}
	
	public List<String> getChannelTypeSelectContents(){
		List<WebElement> loc = channelTypeSelect.getOptions();
		List<String> businesses = new ArrayList<String>();
		for(WebElement el : loc){
			businesses.add(el.getText());
		}
		return businesses;
	}


}