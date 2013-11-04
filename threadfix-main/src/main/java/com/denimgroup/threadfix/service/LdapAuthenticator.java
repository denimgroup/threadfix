package com.denimgroup.threadfix.service;

import org.jfree.util.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;

import com.denimgroup.threadfix.data.entities.CustomUserMapper;
import com.denimgroup.threadfix.plugin.ldap.LdapServiceDelegateFactory;


public class LdapAuthenticator implements LdapService {
	
	@Autowired
	CustomUserMapper customUserMapper;
	
	@Autowired
	DefaultConfigService defaultConfigService;
	
	private LdapService delegate = null;
	
	public LdapAuthenticator(){
		delegate = LdapServiceDelegateFactory.getDelegate();
	}

	@Override
	public Authentication authenticate(Authentication authentication){
		Log.info("Enterprise: "+LdapServiceDelegateFactory.isEnterprise());
		return delegate.authenticate(authentication);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return delegate.supports(authentication);
	}

	@Override
	public boolean innerAuthenticate(String username, String password) {
		return delegate.innerAuthenticate(username, password);
	}


}
