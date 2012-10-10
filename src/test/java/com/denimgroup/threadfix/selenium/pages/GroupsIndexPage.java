package com.denimgroup.threadfix.selenium.pages;

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class GroupsIndexPage extends BasePage {
	
	private WebElement backToMenuLink;
	private WebElement createGroupLink;
	
	private List<WebElement> names = new ArrayList<WebElement>();
	private List<WebElement> parentGroups = new ArrayList<WebElement>();
	private List<WebElement> teamNames = new ArrayList<WebElement>();
	private List<WebElement> editLinks = new ArrayList<WebElement>();
	private List<WebElement> deleteButtons = new ArrayList<WebElement>();
	private List<WebElement> userConfigLinks = new ArrayList<WebElement>();

	public GroupsIndexPage(WebDriver webdriver) {
		super(webdriver);
		backToMenuLink = driver.findElementById("backToMenuLink");
		createGroupLink = driver.findElementById("createNewGroupLink");
		
		for (int i = 1; i <= getNumRows(); i++) {
			names.add(driver.findElementById("group" + i));
			parentGroups.add(driver.findElementById("parentGroup" + i));
			teamNames.add(driver.findElementById("team" + i));
			editLinks.add(driver.findElementById("edit" + i));
			deleteButtons.add(driver.findElementById("delete" + i));
			userConfigLinks.add(driver.findElementById("userConfig" + i));
		}
	}
	
	public ConfigurationIndexPage clickBackToMenuLink() {
		backToMenuLink.click();
		return new ConfigurationIndexPage(driver);
	}
	
	public GroupCreatePage clickCreateGroupLink() {
		createGroupLink.click();
		return new GroupCreatePage(driver);
	}

	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("bodyRow");
		
		if (bodyRows != null && bodyRows.size() == 1 && 
				bodyRows.get(0).getText().trim().equals("No groups found.")) {
			return 0;
		}		
		
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	public String getNameContents(int row) {
		return names.get(row).getText();
	}
	
	public String getTeamName(int row) {
		return teamNames.get(row).getText();
	}

	public String getParentGroupName(int row) {
		return parentGroups.get(row).getText();
	}
	
	public GroupsIndexPage clickDeleteButton(int row) {
		deleteButtons.get(row).click();
		handleAlert();
		return new GroupsIndexPage(driver);
	}
	
	public GroupsIndexPage createGroup(String name, String teamName, 
			String parentGroupName) {
		
		GroupCreatePage page = clickCreateGroupLink();
		
		if (name != null) {
			page.setNameInput(name);
		}
		
		if (teamName != null) {
			page.setTeamSelect(teamName);
		}

		if (parentGroupName != null) {
			page.setParentGroup(parentGroupName);
		}
		
		return page.clickCreateGroupButton().clickSubmitButton();
	}
	
	public GroupEditPage clickEditLink(int row) {
		editLinks.get(row).click();
		return new GroupEditPage(driver);
	}
	
	public GroupUserConfigPage clickUserConfigLink(int row) {
		userConfigLinks.get(row).click();
		return new GroupUserConfigPage(driver);
	}
}
