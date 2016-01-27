////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.entities.Role;

public interface RoleService {
	
	// TODO switch to a bean or enum return
	public static final String SUCCESS = "Success";
	public static final String FIELD_ERROR = "Field Error";

	/**
	 * 
	 * @param role
	 */
	String validateRole(Role role, BindingResult result);
	
	/**
	 * 
	 * @return
	 */
	List<Role> loadAll();

	/**
	 *
	 * @return
	 */
	List<Role> loadAllWithCanDeleteSet();
	
	/**
	 * 
	 * @param id
	 * @return
	 */
	Role loadRole(int id);
	
	/**
	 * 
	 * @param name
	 * @return
	 */
	Role loadRole(String name);

	/**
	 * 
	 * @param id
	 */
	void deactivateRole(int id);
	
	/**
	 * 
	 * @param role
	 */
	void storeRole(Role role);

	/**
	 * We need to avoid a state where no users can perform administrative functions
	 * and the system becomes unusable.
	 * @param role
	 * @return
	 */
	boolean canDelete(Role role);
	
}
