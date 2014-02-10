package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.security.authentication.AuthenticationProvider;

public interface LdapService extends AuthenticationProvider {
	
	boolean innerAuthenticate(String username, String password);
	
	void setLogger(SanitizedLogger log);
}
