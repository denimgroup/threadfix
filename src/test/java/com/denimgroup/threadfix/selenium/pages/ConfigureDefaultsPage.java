package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

public class ConfigureDefaultsPage extends BasePage {
	
	private Select roleSelect;
	private WebElement globalGroupEnabledCheckbox;
	private WebElement updateDefaultsButton;

	public ConfigureDefaultsPage(WebDriver webdriver) {
		super(webdriver);
		
		roleSelect = new Select(driver.findElementById("roleSelect"));
		globalGroupEnabledCheckbox = driver.findElementById("globalGroupEnabledCheckbox");
		updateDefaultsButton = driver.findElementById("updateDefaultsButton");
	}
	
	public ConfigureDefaultsPage setRoleSelect(String code){
		roleSelect.selectByVisibleText(code);
		return this;
	}

	public ConfigureDefaultsPage checkGlobalGroupCheckbox() {
		globalGroupEnabledCheckbox.click();
		return this;
	}
	
	public ConfigurationIndexPage clickUpdateDefaults() {
		updateDefaultsButton.click();
		return new ConfigurationIndexPage(driver);
	}
}
