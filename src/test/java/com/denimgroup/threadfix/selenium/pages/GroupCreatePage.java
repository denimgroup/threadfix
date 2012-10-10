package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class GroupCreatePage extends BasePage {
	
	private WebElement createGroupButton;
	private WebElement backToGroupsLink;
	private WebElement nameInput;

	public GroupCreatePage(WebDriver webdriver) {
		super(webdriver);
		nameInput = driver.findElementById("name");
		createGroupButton = driver.findElementById("createGroupButton");
		backToGroupsLink = driver.findElementById("backToGroupsButton");
	}
	
	public String getNameError() {
		return driver.findElementById("name.errors").getText();
	}
	
	public String getParentGroupIdError() {
		return driver.findElementById("parentGroup.id").getText();
	}
	
	public GroupCreatePage setNameInput(String name) {
		nameInput.sendKeys(name);
		return new GroupCreatePage(driver);
	}
	
	public GroupCreatePage setParentGroup(String groupName) {
		new Select(driver.findElementById("parentGroupId")).selectByVisibleText(groupName);
		return this;
	}
	
	public GroupCreatePage setTeamSelect(String teamName) {
		new Select(driver.findElementById("teamId")).selectByVisibleText(teamName);
		return this;
	}
	
	public GroupUserConfigPage clickCreateGroupButton() {
		createGroupButton.click();
		return new GroupUserConfigPage(driver);
	}
	
	public GroupCreatePage clickCreateGroupButtonInvalid() {
		createGroupButton.click();
		return new GroupCreatePage(driver);
	}
	
	public GroupsIndexPage clickBackToIndexLink() {
		backToGroupsLink.click();
		return new GroupsIndexPage(driver);	
	}
}
