package com.denimgroup.threadfix.plugin.ldap;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.denimgroup.threadfix.data.entities.CustomUserMapper;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.LdapService;

public class DefaultLdapServiceDelegate implements LdapService {

	
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
	
	

}
