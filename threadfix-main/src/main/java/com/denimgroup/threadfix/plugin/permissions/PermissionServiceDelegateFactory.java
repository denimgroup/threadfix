package com.denimgroup.threadfix.plugin.permissions;

import com.denimgroup.threadfix.service.PermissionService;

public class PermissionServiceDelegateFactory {

	public static PermissionService getDelegate() {
		PermissionService delegate = null;//PluginLoader.getMostRecentPlugin(PermissionService.class);
		
		if (delegate == null) {
			delegate = new DefaultPermissionServiceDelegate();
		}
		
		return delegate;
	}
	
	public static boolean isEnterprise() {
		return !(getDelegate() instanceof DefaultPermissionServiceDelegate);
	}
	
}
