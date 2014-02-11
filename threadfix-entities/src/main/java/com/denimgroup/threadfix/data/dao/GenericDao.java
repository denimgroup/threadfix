////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.data.dao;

import java.util.List;

/**
 * Generic interface for entities.
 * 
 * @author jraim
 * 
 * @param <T>
 *            The type of the entity the DAO will act upon.
 */
public interface GenericDao<T> {

	/**
	 * Retrieves all objects of the specified type.
	 * 
	 * @return A list of all objects of the specified type or an empty list if
	 *         no objects exist
	 */
	List<T> retrieveAll();

	/**
	 * Retrieves the object by the specified id.
	 * 
	 * @param id
	 *            The id of the object to retrieve.
	 * @return The object or NULL if not found.
	 */
	T retrieveById(int id);

	/**
	 * If the ID on the objects are valid, then they will be updated. If the IDs
	 * are not valid, new objects will be persisted.
	 * 
	 * @param objectsToPersist
	 *            A list of objects to persist.
	 */
	void saveOrUpdate(List<T> objectsToPersist);

	/**
	 * If the ID on the object is valid, then it will be updated. If the ID is
	 * not valid a new object will be persisted.
	 * 
	 * @param objectToPersist
	 *            The object to save or update.
	 */
	void saveOrUpdate(T objectToPersist);

}
