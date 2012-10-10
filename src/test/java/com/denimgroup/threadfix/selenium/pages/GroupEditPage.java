package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class GroupEditPage extends BasePage {
	
	private WebElement createGroupButton;
	private WebElement backToGroupsLink;
	private WebElement nameInput;
	private Select parentGroupSelect;
	private Select teamSelect;

	public GroupEditPage(WebDriver webdriver) {
		super(webdriver);
		nameInput = driver.findElementById("name");
		parentGroupSelect = new Select(driver.findElementById("parentGroupId"));
		teamSelect = new Select(driver.findElementById("teamId"));
		createGroupButton = driver.findElementById("updateGroupButton");
		backToGroupsLink = driver.findElementById("backToGroupsButton");

	}

	public String getNameError() {
		return driver.findElementById("name.errors").getText();
	}
	
	public String getParentGroupIdError() {
		return driver.findElementById("parentGroup.id.errors").getText();
	}
	
	public GroupEditPage setNameInput(String name) {
		nameInput.clear();
		nameInput.sendKeys(name);
		return this;
	}
	
	public GroupEditPage setParentGroup(String groupName) {
		parentGroupSelect.selectByVisibleText(groupName);
		return this;
	}
	
	public GroupEditPage setTeamSelect(String teamName) {
		teamSelect.selectByVisibleText(teamName);
		return this;
	}
	
	public GroupsIndexPage clickUpdateGroupButton() {
		createGroupButton.click();
		return new GroupsIndexPage(driver);
	}
	
	public GroupEditPage clickUpdateGroupButtonInvalid() {
		createGroupButton.click();
		return new GroupEditPage(driver);
	}
	
	public GroupsIndexPage clickBackToIndexLink() {
		backToGroupsLink.click();
		return new GroupsIndexPage(driver);	
	}
}
