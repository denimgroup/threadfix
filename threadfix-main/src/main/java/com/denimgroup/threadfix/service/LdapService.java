package com.denimgroup.threadfix.service;

import org.springframework.security.authentication.AuthenticationProvider;

import com.denimgroup.threadfix.data.entities.CustomUserMapper;

import net.xeoh.plugins.base.Plugin;

public interface LdapService extends Plugin,AuthenticationProvider {
	
	boolean innerAuthenticate(String username, String password);
}
