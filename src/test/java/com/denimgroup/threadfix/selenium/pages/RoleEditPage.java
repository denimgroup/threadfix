package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class RoleEditPage extends BasePage {
	
	private WebElement createRoleButton;
	private WebElement backToRolesLink;
	private WebElement nameInput;

	public RoleEditPage(WebDriver webdriver) {
		super(webdriver);
		nameInput = driver.findElementById("displayName");
		createRoleButton = driver.findElementById("updateRoleButton");
		backToRolesLink = driver.findElementById("backToRolesButton");
	}

	public String getNameError() {
		return driver.findElementById("name.errors").getText();
	}

	public RoleEditPage setNameInput(String name) {
		nameInput.clear();
		nameInput.sendKeys(name);
		return this;
	}
	
	public RolesIndexPage clickUpdateRoleButton() {
		createRoleButton.click();
		return new RolesIndexPage(driver);
	}
	
	public RoleEditPage clickUpdateRoleButtonInvalid() {
		createRoleButton.click();
		return new RoleEditPage(driver);
	}
	
	public RolesIndexPage clickBackToIndexLink() {
		backToRolesLink.click();
		return new RolesIndexPage(driver);	
	}
	
	public String getPermissionError(String permissionName) {
		return driver.findElementById(permissionName + "Error").getText();
	}
	
	public boolean getPermissionValue(String permissionName) {
		return driver.findElementById(permissionName + "True").isSelected();
	}
	
	public RoleEditPage setPermissionValue(String permissionName, boolean value) {
		
		String target = value ? "True" : "False";
		driver.findElementById(permissionName + target).click();
		
		return this;
	}
}
