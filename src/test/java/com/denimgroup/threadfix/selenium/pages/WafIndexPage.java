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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

public class WafIndexPage extends BasePage {

	private WebElement addWafLink;
	private WebDriverWait wait = new WebDriverWait(driver,10);
	private List<WebElement> names = new ArrayList<WebElement>();
	
	public WafIndexPage(WebDriver webdriver) {
		super(webdriver);
		addWafLink = driver.findElementById("addWafModalButton");
		for (int i = 1; i <= getNumRows(); i++) {
			names.add(driver.findElementById("wafName" + i));
		}
	}
	
	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("bodyRow");
		
		if (bodyRows != null && bodyRows.size() == 1 && bodyRows.get(0).getText().trim().contains("No WAFs found.")) {
			return 0;
		}		
		
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	public int getIndex(String roleName) {
		int i = -1;
		for (WebElement name : names) {
			i++;
			String text = name.getText().trim();
			if (text.equals(roleName.trim())) {
				return i;
			}
		}
		return -1;
	}
	
	public WafDetailPage clickRules(String wafName){
		driver.findElementsByLinkText("Rules").get(getIndex(wafName)).click();
		return new WafDetailPage(driver);
	}
/*
	public WafIndexPage clickDeleteWaf(int i){
		driver.findElementById("deleteWaf"+i).click();
		handleAlert();
		return new WafIndexPage(driver);
	}
	*/
	public WafIndexPage clickDeleteWaf(String wafName){
		System.out.println("Wafname = " + wafName);
		System.out.println("Index is " + getIndex(wafName));
		driver.findElementById("deleteWaf"+ (getIndex(wafName) + 1)).click();
		handleAlert();
		return new WafIndexPage(driver);
	}

	public WafIndexPage clickAddWafLink() {
		addWafLink.click();
		waitForElement(driver.findElementById("createWaf"));
		return new WafIndexPage(driver);
	}
	
	public WafIndexPage createNewWaf(String name,String Type){
		setNewNameInput(name);
		setType(null,Type);
		return this;
	}
	
	public WafIndexPage clickCreateWaf(){
		driver.findElementById("submitWafModal").click();
		waitForInvisibleElement(driver.findElementById("createWaf"));
		return new WafIndexPage(driver);
	}
	
	public WafIndexPage clickCreateWafInvalid(){
		driver.findElementsById("submitWafModal").get(names.size()).click();
		return new WafIndexPage(driver);
	}
	
	

	public boolean isTextPresentInWafTableBody(String text) {
		return driver.findElementById("wafTableBody").getText().contains(text);
	}
	
	public boolean isNamePresent(String wafName){
		for(int i=0;i<getNumRows();i++){
			if(names.get(i).equals(wafName)){
				return true;
			}
		}
		return false;
	}
	
	
/*	public WafIndexPage clickEditWaf(int i){
		driver.findElementById("editWafModalButton"+i).click();
		waitForElement(driver.findElementByClassName("modal"));
		return new WafIndexPage(driver);
	}*/
	
	public WafIndexPage clickEditWaf(String wafName){
		driver.findElementById("editWafModalButton"+getIndex(wafName)).click();
		waitForElement(driver.findElementByClassName("modal"));
		return new WafIndexPage(driver);
	}
	
	public WafIndexPage editWaf(String wafName, String newName, String type){
		driver.findElementById("nameInput").clear();
		driver.findElementById("nameInput").sendKeys(newName);
		new Select(driver.findElementById("typeSelect")).selectByVisibleText(type);
		return new WafIndexPage(driver);
	}
	
	public WafIndexPage clickUpdateWaf(){
		driver.findElementByLinkText("Update WAF").click();
		waitForInvisibleElement(driver.findElementByClassName("modal"));
		return new WafIndexPage(driver);
	}
	
	public WafIndexPage clickUpdateWafInvalid(){
		driver.findElementByLinkText("Update WAF").click();
		return new WafIndexPage(driver);
	}
	
	public String getWafName(int row){
		return driver.findElementById("wafName" + row).getText();
	}


	
	public WafIndexPage setNewNameInput(String name){
		driver.findElementById("wafCreateNameInput").clear();
		driver.findElementById("wafCreateNameInput").sendKeys(name);
		return this;
	}
	
	public WafIndexPage setNameInput(String oldName,String newName){
		driver.findElementsById("nameInput").get(getIndex(oldName)).clear();
		driver.findElementsById("nameInput").get(getIndex(oldName)).sendKeys(newName);
		return this;
	}
	
	public String getSuccessAlert(){
		return driver.findElementByClassName("alert-success").getText();
	}
	
	public WafIndexPage setType(String oldName,String type){
		if(oldName==null){
			new Select(driver.findElementsById("typeSelect").get(names.size())).selectByVisibleText(type);
		}else{
			new Select(driver.findElementsById("typeSelect").get(getIndex(oldName))).selectByVisibleText(type);
		}
		return this;
	}
	
	public String getNameErrorsText(){
		return driver.findElementById("name.errors").getText();
	}

	public String getNameText(int row){
		return  driver.findElementById("wafName" + row).getText();
	}
}
