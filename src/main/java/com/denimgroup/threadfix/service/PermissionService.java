package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.Permission;

public interface PermissionService {

	/**
	 * 
	 * @param orgId
	 * @return
	 */
	boolean isAuthorized(Permission permission, Integer orgId, Integer teamId);
}
