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

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ApplicationVersionDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationVersion;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import java.util.List;
import java.util.Map;

@Service
@Transactional(readOnly = false) // used to be true
public class ApplicationVersionServiceImpl implements ApplicationVersionService {

	protected final SanitizedLogger log = new SanitizedLogger(ApplicationVersionServiceImpl.class);

	@Autowired
	private ApplicationVersionDao applicationVersionDao ;
	@Autowired
	private ApplicationDao applicationDao;


	@Override
	public Map<String, Object> getAllVersionsByAppId(List<Integer> appIds) {
		return applicationVersionDao.getAllVersionsByAppId(appIds);
	}

	@Override
	public ApplicationVersion loadVersion(int versionId) {
		return applicationVersionDao.retrieveById(versionId);
	}

	@Override
	public ApplicationVersion loadAppVersionByName(String name, int appId) {
		return applicationVersionDao.loadAppVersionByName(name, appId);
	}

	@Override
	public void storeVersion(ApplicationVersion version) {
		applicationVersionDao.saveOrUpdate(version);
	}

	@Override
	public void validate(ApplicationVersion applicationVersion, BindingResult result, int appId) {
		if (result.hasErrors())
			return;

		if (applicationVersion.getName() == null || applicationVersion.getName().trim().isEmpty()) {
			result.rejectValue("name", null, null, "Name cannot be blank");
		}
		applicationVersion.setName(applicationVersion.getName().trim());

		if (applicationVersion.getDate() == null) {
			result.rejectValue("date", null, null, "Date cannot be blank");
		}

		Application application = applicationDao.retrieveById(appId);
		if (application == null) {
			result.rejectValue("name", null, null, "Application is invalid");
		}
		applicationVersion.setApplication(application);

		ApplicationVersion dbVersion = loadAppVersionByName(applicationVersion.getName(), appId);
		if (applicationVersion.getId() == null) { // create new version
			if (dbVersion != null)
				result.rejectValue("name", null, null, "This name is already taken");
		} else {
			// There is another version in application with the same name
			if (dbVersion != null) {
				if (dbVersion.getId().compareTo(applicationVersion.getId()) != 0) {
					result.rejectValue("name", null, null, "This name is already taken");
				}

				if (dbVersion.getApplication().getId() != appId) {
					result.rejectValue("name", null, null, "Application is invalid");
				}
			}
		}
	}

	@Override
	public void delete(ApplicationVersion version) {
		version.setApplication(null);
		applicationVersionDao.delete(version);
	}
}
