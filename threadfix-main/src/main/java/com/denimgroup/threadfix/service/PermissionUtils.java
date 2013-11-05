package com.denimgroup.threadfix.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.denimgroup.threadfix.data.entities.Permission;

public final class PermissionUtils {

	private PermissionUtils() {
		// This prevents instantiation of this class
	}
	
	public static boolean hasGlobalPermission(Permission permission) {
		if (permission == null || permission.getText() == null) {
			return false;
		}
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		return authentication != null && authentication
				.getAuthorities().contains(new SimpleGrantedAuthority(permission.getText()));
	}

	public static boolean hasGlobalReadAccess() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		return authentication != null && authentication.getAuthorities().contains(
						new SimpleGrantedAuthority(Permission.READ_ACCESS.getText()));
	}
}
