package com.denimgroup.threadfix.selenium.pages;

import org.openqa.selenium.WebDriver;

/**
 * Created by mghanizadeh on 9/22/2014.
 */
public class WafRulesDetailPage extends BasePage {
    public WafRulesDetailPage(WebDriver webdriver) {
        super(webdriver);
    }

    public WafSecurityEventDetailsPage clickVulnerabilityLink() {
        driver.findElementByLinkText("8/2/14 2:58:37 PM -- \"SQL Injection attempt\"").click();
        return new WafSecurityEventDetailsPage(driver);
    }
}
