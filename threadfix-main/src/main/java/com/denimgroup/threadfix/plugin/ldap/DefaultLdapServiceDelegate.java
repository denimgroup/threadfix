package com.denimgroup.threadfix.plugin.ldap;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.denimgroup.threadfix.service.LdapService;
import com.denimgroup.threadfix.service.SanitizedLogger;

public class DefaultLdapServiceDelegate implements LdapService {

	protected SanitizedLogger log = null;
	
	public DefaultLdapServiceDelegate(){
		
	}
	
	@Override
	public boolean innerAuthenticate(String username, String password){
		return false;
	}

	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		return null;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return false;
	}
	
	@Override
	public void setLogger(SanitizedLogger log){
		this.log = log;
	}
	
	

}
