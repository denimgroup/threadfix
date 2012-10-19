package com.denimgroup.threadfix.selenium.pages;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverBackedSelenium;
import org.openqa.selenium.WebElement;

import com.thoughtworks.selenium.Selenium;

public class RoleUserConfigPage extends BasePage {
	
	private List<WebElement> userNames = new ArrayList<WebElement>();
	private List<WebElement> groupIdCheckBoxes = new ArrayList<WebElement>();
	private WebElement backToMenuLink;
	private WebElement submitButton;
	private Map<String, WebElement> nameCheckedMap = new HashMap<String, WebElement>();
	
	public RoleUserConfigPage(WebDriver webdriver) {
		super(webdriver);
		for (int i = 1; i <= getNumRows(); i++) {
			nameCheckedMap.put(driver.findElementById("name" + i).getText(), 
					driver.findElementById("userIds" + i));
			
			userNames.add(driver.findElementById("name" + i));
			groupIdCheckBoxes.add(driver.findElementById("userIds" + i));
		}

		backToMenuLink = driver.findElementById("backToRolesPage");
		submitButton = driver.findElementById("submitButton");
	}
	
	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("bodyRow");
		if (bodyRows != null && bodyRows.size() == 1 && 
				bodyRows.get(0).getText().trim().equals("No users found.")) {
			return 0;
		}		
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	public boolean isChecked(int row) {
		return "checked".equals("userIds" + row);
	}
	
	public boolean isChecked(String userName) {
		boolean checked = false;
		
		for (int i = 0; i < userNames.size(); i++) {
			if (userNames.get(i).getText().equals(userName)) {
				Selenium selenium = new WebDriverBackedSelenium(driver, driver.getCurrentUrl());
				checked = selenium.isChecked("userIds" + (i + 1));
				break;
			}
		}
		
		return checked;
	}
	
	public RoleUserConfigPage toggleUserIdBox(int row) {
		
		Selenium selenium = new WebDriverBackedSelenium(driver, driver.getCurrentUrl());
		selenium.click("userIds" + row);
		
		return this;
	}
	
	public RoleUserConfigPage toggleUserIdBox(String userName, boolean on) {
		
		for (int i = 0; i < userNames.size(); i++) {
			if (userNames.get(i).getText().equals(userName)) {
				Selenium selenium = new WebDriverBackedSelenium(driver, driver.getCurrentUrl());
				if (on)
					selenium.check("userIds" + (i + 1));
				else
					selenium.uncheck("userIds" + (i + 1));
				break;
			}
		}
		
		return this;
	}
	
	public String getUserNameText(int row) {
		return userNames.get(row).getText();
	}
	
	public RolesIndexPage clickBackToMenuLink() {
		backToMenuLink.click();
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage clickSubmitButton() {
		submitButton.click();
		return new RolesIndexPage(driver);
	}

}