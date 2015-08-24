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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.service.beans.ScanParametersBean;

@Service
@Transactional(readOnly=false)
public class ScanParametersServiceImpl implements ScanParametersService {

	private ApplicationDao applicationDao;
	
	@Autowired 
	ScanParametersServiceImpl(ApplicationDao applicationDao) {
		this.applicationDao = applicationDao;
	}
	
	@Override
	public boolean saveConfiguration(Integer appId,
			ScanParametersBean scanParametersBean) {
		if (scanParametersBean != null && appId != null) {
			return saveConfiguration(applicationDao.retrieveById(appId), scanParametersBean);
		} else {
			return false;
		}
	}
	
	@Override
	public boolean saveConfiguration(Application application,
			ScanParametersBean scanParametersBean) {
		
		boolean result = false;
		
		if (scanParametersBean != null && application != null) {
			
			FrameworkType frameworkType = 
					FrameworkType.getFrameworkType(scanParametersBean.getApplicationType());
			SourceCodeAccessLevel accessLevel = 
					SourceCodeAccessLevel.getSourceCodeAccessLevel(scanParametersBean.getSourceCodeAccessLevel());
			
			application.setFrameworkType(frameworkType.toString());
			application.setSourceCodeAccessLevel(accessLevel.toString());
			
			if (scanParametersBean.getSourceCodeUrl() != null && 
					scanParametersBean.getSourceCodeUrl().length() < Application.URL_LENGTH) {
				application.setRepositoryUrl(scanParametersBean.getSourceCodeUrl());

				if (application.getRepositoryType() == null || "".equals(application.getRepositoryType())) {
					application.setRepositoryType("GIT");
				}
			}
			
			applicationDao.saveOrUpdate(application);
			result = true;
		}
		
		return result;
	}
}
