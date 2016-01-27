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

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ExceptionLog;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.beans.ScanParametersBean;
import com.denimgroup.threadfix.service.repository.RepositoryServiceFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly=false)
public class ScanParametersServiceImpl implements ScanParametersService {

	private final SanitizedLogger log = new SanitizedLogger(ScanParametersServiceImpl.class);

	private ApplicationDao applicationDao;
	@Autowired
	private RepositoryServiceFactory repositoryServiceFactory;
	@Autowired
	private ExceptionLogService exceptionLogService;

	@Autowired 
	ScanParametersServiceImpl(ApplicationDao applicationDao) {
		this.applicationDao = applicationDao;
	}
	
	@Override
	public String saveConfiguration(Application application,
			ScanParametersBean scanParametersBean) {
		
		if (scanParametersBean != null && application != null) {
			
			FrameworkType frameworkType = 
					FrameworkType.getFrameworkType(scanParametersBean.getApplicationType());
			SourceCodeAccessLevel accessLevel = 
					SourceCodeAccessLevel.getSourceCodeAccessLevel(scanParametersBean.getSourceCodeAccessLevel());
			
			application.setFrameworkType(frameworkType.toString());
			application.setSourceCodeAccessLevel(accessLevel.toString());

			if (scanParametersBean.getSourceCodeUrl() != null &&
					scanParametersBean.getSourceCodeUrl().length() < Application.URL_LENGTH) {
				if (checkRepository(application, scanParametersBean.getSourceCodeUrl())) {
					application.setRepositoryUrl(scanParametersBean.getSourceCodeUrl());

					if (application.getRepositoryType() == null || "".equals(application.getRepositoryType())) {
						application.setRepositoryType("GIT");
					}
				} else {
					return "Unable to clone repository";
				}
			}

			applicationDao.saveOrUpdate(application);
		}

		return null;
	}

	private boolean checkRepository(Application application, String repository) {
		RepositoryService repositoryService = repositoryServiceFactory.getRepositoryService("GIT");
		try {
			if (!repositoryService.testConfiguration(application, repository, application.getRepositoryBranch()))
                return false;
		} catch (Exception e) {
			log.info("Got an error, logging to database (visible under Error Messages)");
			exceptionLogService.storeExceptionLog(new ExceptionLog(e));
			return false;
		}
		return true;
	}
}
