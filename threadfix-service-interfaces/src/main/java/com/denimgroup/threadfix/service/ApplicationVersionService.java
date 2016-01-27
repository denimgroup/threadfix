////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.APIKey;
import com.denimgroup.threadfix.data.entities.ApplicationVersion;
import org.springframework.validation.BindingResult;

import java.util.List;
import java.util.Map;

/**
 * @author stran
 * 
 */
public interface ApplicationVersionService {

	/**
	 * @return
	 */
	Map<String, Object> getAllVersionsByAppId(List<Integer> appIds);

	/**
	 * @param versionId
	 * @return
	 */
	ApplicationVersion loadVersion(int versionId);

	/**
	 *
	 * @param name
	 * @param appId
	 * @return
	 */
	ApplicationVersion loadAppVersionByName(String name, int appId);

	/**
	 * @param version
	 */
	void storeVersion(ApplicationVersion version);

	void validate(ApplicationVersion applicationVersion, BindingResult result, int appId);

	void delete(ApplicationVersion version);
}
