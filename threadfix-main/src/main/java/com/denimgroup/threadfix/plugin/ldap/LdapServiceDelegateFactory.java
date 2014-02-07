package com.denimgroup.threadfix.plugin.ldap;

import com.denimgroup.threadfix.service.LdapService;

public class LdapServiceDelegateFactory {
	public static LdapService getDelegate() {

        // TODO autowire this
		LdapService delegate = null;//PluginLoader.getMostRecentPlugin(LdapService.class);
		
		if (delegate == null) {
			delegate = new DefaultLdapServiceDelegate();
		}
		
		return delegate;
	}
	
	public static boolean isEnterprise() {
		return !(getDelegate() instanceof DefaultLdapServiceDelegate);
	}
	
}

