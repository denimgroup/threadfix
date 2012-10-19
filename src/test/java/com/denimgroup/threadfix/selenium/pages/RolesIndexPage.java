package com.denimgroup.threadfix.selenium.pages;

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

public class RolesIndexPage extends BasePage {

	private WebElement backToMenuLink;
	private WebElement createRoleLink;
	
	private List<WebElement> names = new ArrayList<WebElement>();
	private List<WebElement> editLinks = new ArrayList<WebElement>();
	private List<WebElement> deleteButtons = new ArrayList<WebElement>();
	private List<WebElement> userConfigLinks = new ArrayList<WebElement>();

	public RolesIndexPage(WebDriver webdriver) {
		super(webdriver);
		backToMenuLink = driver.findElementById("backToMenuLink");
		createRoleLink = driver.findElementById("createNewRoleLink");
		
		for (int i = 1; i <= getNumRows(); i++) {
			names.add(driver.findElementById("role" + i));
			editLinks.add(driver.findElementById("edit" + i));
			deleteButtons.add(driver.findElementById("delete" + i));
			userConfigLinks.add(driver.findElementById("userConfig" + i));
		}
	}
	
	public ConfigurationIndexPage clickBackToMenuLink() {
		backToMenuLink.click();
		return new ConfigurationIndexPage(driver);
	}
	
	public RoleCreatePage clickCreateRoleLink() {
		createRoleLink.click();
		return new RoleCreatePage(driver);
	}

	public int getNumRows() {
		List<WebElement> bodyRows = driver.findElementsByClassName("bodyRow");
		
		if (bodyRows != null && bodyRows.size() == 1 && 
				bodyRows.get(0).getText().trim().equals("No roles found.")) {
			return 0;
		}		
		
		return driver.findElementsByClassName("bodyRow").size();
	}
	
	public String getNameContents(int row) {
		return names.get(row).getText();
	}
	
	public RolesIndexPage clickDeleteButton(int row) {
		deleteButtons.get(row).click();
		handleAlert();
		return new RolesIndexPage(driver);
	}
	
	public RolesIndexPage clickDeleteButton(String roleName) {
		deleteButtons.get(getIndex(roleName)).click();
		handleAlert();
		return new RolesIndexPage(driver);
	}
	
	private int getIndex(String roleName) {
		int i = 0;
		for (WebElement name : names) {
			if (name.getText().equals(roleName)) {
				return i;
			}
			i++;
		}
		return 0;
	}
	
	public RolesIndexPage createRole(String displayName) {
		
		RoleCreatePage page = clickCreateRoleLink();
		
		if (displayName != null) {
			page.setDisplayNameInput(displayName);
		}
		
		return page.clickCreateRoleButton().clickSubmitButton();
	}
	
	public RoleEditPage clickEditLink(int row) {
		editLinks.get(row).click();
		return new RoleEditPage(driver);
	}

	public RoleEditPage clickEditLink(String roleName) {
		editLinks.get(getIndex(roleName)).click();
		return new RoleEditPage(driver);
	}
	
	public RoleUserConfigPage clickUserConfigLink(int row) {
		userConfigLinks.get(row).click();
		return new RoleUserConfigPage(driver);
	}
	
}
