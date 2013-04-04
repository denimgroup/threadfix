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

import org.openqa.selenium.Alert;
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
	private List<WebElement> types = new ArrayList<WebElement>();
	private List<WebElement> editButtons = new ArrayList<WebElement>();
	private List<WebElement> deleteButtons = new ArrayList<WebElement>();
	private List<WebElement> rulesButtons = new ArrayList<WebElement>();
	
	public WafIndexPage(WebDriver webdriver) {
		super(webdriver);
		if(!driver.findElementById("wafTableBody").getText().contains("No WAFs found.")){
			if(getNumRows()!=0){
				types = driver.findElementsByClassName("details");
				editButtons = driver.findElementsByLinkText("Edit WAF");
				deleteButtons = driver.findElementsByLinkText("Delete");
				rulesButtons = driver.findElementsByLinkText("Rules");
				names = driver.findElementsByClassName("details");
			
			}
		}
		
		addWafLink = driver.findElementById("addWafModalButton");
	}
	
	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("bodyRow");
		
		if (bodyRows != null && bodyRows.size() == 1 && bodyRows.get(0).getText().trim().equals("No wafs found.")) {
			return 0;
		}		
		
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	public WafDetailPage clickRules(String wafName){
		for(int i=0;i<names.size();i++){
			if(names.get(i).getText().contains(wafName)){
				rulesButtons.get(i).click();
				break;
			}
		}
		return new WafDetailPage(driver);
	}
	
	public WafIndexPage clickDeleteWaf(String wafName){
		for(int i=0;i<names.size();i++){
			if(names.get(i).getText().contains(wafName)){
				deleteButtons.get(i).click();
				break;
			}
		}
		Alert alert = driver.switchTo().alert();
		alert.accept();
		return new WafIndexPage(driver);
	}

	public WafIndexPage clickAddWafLink() {
		addWafLink.click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("createWaf")));
		return new WafIndexPage(driver);
	}
	
	public WafIndexPage createNewWaf(String name,String Type){
		driver.findElementById("createWaf").findElement(By.id("nameInput")).sendKeys(name);
		new Select(driver.findElementById("createWaf").findElement(By.id("typeSelect"))).selectByVisibleText(Type);
		driver.findElementById("createWaf").findElement(By.id("submitWafModal")).click();
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.id("createWaf")));
		return new WafIndexPage(driver);
	}
	

	public boolean isTextPresentInWafTableBody(String text) {
		for (int i = 1; i <= getNumRows(); i++){
			if(names.get(i).getText().equals(text)||types.get(i).getText().equals(text)){
				return true;
			}
		}
		return false;
	}
	
	public int wafRowNumber(String wafName){
		int i;
		for (i = 1; i <= getNumRows(); i++){
			if(names.get(i).getText().equals(wafName)){
				break;
			}
		}
		return i;
	}
	
	public WafIndexPage editWaf(String wafName, String name, String type){
		editButtons.get(wafRowNumber(wafName)).click();
		wait.until(ExpectedConditions.visibilityOfElementLocated(By.className("modal")));
		driver.findElementById("nameInput").sendKeys(name);
		new Select(driver.findElementById("typeSelect")).selectByVisibleText(type);
		driver.findElementByLinkText("Update WAF");
		wait.until(ExpectedConditions.invisibilityOfElementLocated(By.className("modal")));
		return new WafIndexPage(driver);
	}
	
	public WafIndexPage deleteWaf(String wafName){
		deleteButtons.get(wafRowNumber(wafName)).click();
		 wait.until(ExpectedConditions.alertIsPresent());
	     Alert alert = driver.switchTo().alert();
	     alert.accept();
		return new WafIndexPage(driver);
	}
	
	//TODO add Rules actions
}
