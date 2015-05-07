package com.denimgroup.threadfix.service.email;

import org.springframework.stereotype.Component;

@Component
public class EmailConfiguration {

	private boolean configuredEmail;

	public boolean isConfiguredEmail() {
		return configuredEmail;
	}

	public void setConfiguredEmail(boolean configuredEmail) {
		this.configuredEmail = configuredEmail;
	}
}
