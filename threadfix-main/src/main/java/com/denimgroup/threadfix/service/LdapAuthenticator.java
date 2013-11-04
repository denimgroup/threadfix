package com.denimgroup.threadfix.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;

import com.denimgroup.threadfix.data.entities.CustomUserMapper;
import com.denimgroup.threadfix.plugin.ldap.LdapServiceDelegateFactory;


public class LdapAuthenticator implements LdapService {
	
	@Autowired
	CustomUserMapper customUserMapper;
	
	@Autowired
	DefaultConfigService defaultConfigService;
	
	protected final SanitizedLogger log = new SanitizedLogger(LdapService.class);
	
	private LdapService delegate = null;
	
	public LdapAuthenticator(){
		delegate = LdapServiceDelegateFactory.getDelegate();
	}

	@Override
	public Authentication authenticate(Authentication authentication){
		setLogger(log);
		return delegate.authenticate(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		setLogger(log);
		return delegate.supports(authentication);
	}

	@Override
	public boolean innerAuthenticate(String username, String password) {
		setLogger(log);
		return delegate.innerAuthenticate(username, password);
	}
	
	@Override
	public void setLogger(SanitizedLogger log){
		delegate.setLogger(log);
	}
	


}
