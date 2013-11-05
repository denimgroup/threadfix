package com.denimgroup.threadfix.plugin.ldap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import com.denimgroup.threadfix.service.CustomUserDetailService;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.UserService;

public class LdapDaoHolder extends SpringBeanAutowiringSupport {
	
	@Autowired
	DefaultConfigService defaultConfigService;
	
	@Autowired
	RoleService roleService;
	
	@Autowired
	CustomUserDetailService customUserDetailService;
	
	@Autowired
	UserService userService;
	
}
