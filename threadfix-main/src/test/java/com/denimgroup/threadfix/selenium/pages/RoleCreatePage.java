package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class RoleCreatePage extends BasePage {
	
	private WebElement createRoleButton;
	private WebElement backToRolesLink;
	private WebElement displayNameInput;

	public RoleCreatePage(WebDriver webdriver) {
		super(webdriver);
		displayNameInput = driver.findElementById("displayName");
		createRoleButton = driver.findElementById("createRoleButton");
		backToRolesLink = driver.findElementById("backToRolesButton");
	}
	
	public String getNameError() {
		return driver.findElementById("name.errors").getText();
	}

	public String getDisplayNameError() {
		return driver.findElementById("displayName.errors").getText();
	}

	public RoleCreatePage setDisplayNameInput(String displayName) {
		displayNameInput.sendKeys(displayName);
		return new RoleCreatePage(driver);
	}
	
	public RolesIndexPage clickCreateRoleButton() {
		createRoleButton.click();
		return new RolesIndexPage(driver);
	}
	
	public RoleCreatePage clickCreateRoleButtonInvalid() {
		createRoleButton.click();
		return new RoleCreatePage(driver);
	}
	
	public RolesIndexPage clickBackToIndexLink() {
		backToRolesLink.click();
		return new RolesIndexPage(driver);	
	}
	
	public boolean getCanViewJobStatusesValue() {
		return driver.findElementById("canViewJobStatusesTrue").isSelected();
	}
	
	public boolean getPermissionValue(String permissionName) {
		return driver.findElementById(permissionName + "True").isSelected();
	}
	
	public RoleCreatePage setPermissionValue(String permissionName, boolean value) {
		
		String target = value ? "True" : "False";
		driver.findElementById(permissionName + target).click();
		
		return this;
	}
}
