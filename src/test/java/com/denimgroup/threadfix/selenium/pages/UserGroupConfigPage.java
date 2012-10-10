package com.denimgroup.threadfix.selenium.pages;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class UserGroupConfigPage extends BasePage {
	
	private List<WebElement> groupNames = new ArrayList<WebElement>();
	private List<WebElement> groupIdCheckBoxes = new ArrayList<WebElement>();
	private WebElement backToMenuLink;
	private WebElement submitButton;
	private Map<String, WebElement> nameCheckedMap = new HashMap<String, WebElement>();
	
	public UserGroupConfigPage(WebDriver webdriver) {
		super(webdriver);
		for (int i = 1; i <= getNumRows(); i++) {
			nameCheckedMap.put(driver.findElementById("name" + i).getText(), 
					driver.findElementById("groupIds" + i));
			
			groupNames.add(driver.findElementById("name" + i));
			groupIdCheckBoxes.add(driver.findElementById("groupIds" + i));
		}

		backToMenuLink = driver.findElementById("backToUserPageLink");
		submitButton = driver.findElementById("submitButton");
	}
	
	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("bodyRow");
		if (bodyRows != null && bodyRows.size() == 1 && 
				bodyRows.get(0).getText().trim().equals("No groups found.")) {
			return 0;
		}		
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	public boolean isChecked(int row) {
		return "checked".equals(groupIdCheckBoxes.get(row).getAttribute("checked"));
	}
	
	public boolean isChecked(String userName) {
		return "checked".equals(nameCheckedMap.get(userName).getAttribute("checked"));
	}
	
	public UserGroupConfigPage toggleUserIdBox(int row) {
		groupIdCheckBoxes.get(row).click();
		return this;
	}
	
	public UserGroupConfigPage toggleUserIdBox(String userName) {
		
		for (int i = 0; i < groupNames.size(); i++) {
			if (groupNames.get(i).equals(userName)) {
				groupIdCheckBoxes.get(i).click();
				break;
			}
		}
		
		return this;
	}
	
	public String getUserNameText(int row) {
		return groupNames.get(row).getText();
	}
	
	public UserIndexPage clickBackToMenuLink() {
		backToMenuLink.click();
		return new UserIndexPage(driver);
	}
	
	public UserIndexPage clickSubmitButton() {
		submitButton.click();
		return new UserIndexPage(driver);
	}

}
