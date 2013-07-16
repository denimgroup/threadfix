////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
import com.denimgroup.threadfix.service.merge.FrameworkType;
import com.denimgroup.threadfix.service.merge.SourceCodeAccessLevel;
import com.denimgroup.threadfix.service.merge.VulnTypeStrategy;
import com.denimgroup.threadfix.webapp.viewmodels.ScanParametersBean;

@Service
public class ScanParametersServiceImpl implements ScanParametersService {

	private ApplicationDao applicationDao;
	
	@Autowired 
	ScanParametersServiceImpl(ApplicationDao applicationDao) {
		this.applicationDao = applicationDao;
	}
	
	@Override
	@Transactional(readOnly=false)
	public void saveConfiguration(Integer appId,
			ScanParametersBean scanParametersBean) {
		
		if (scanParametersBean != null && appId != null) {
			Application app = applicationDao.retrieveById(appId);
			
			if (app != null) {
			
				FrameworkType frameworkType = 
						FrameworkType.getFrameworkType(scanParametersBean.getApplicationType());
				SourceCodeAccessLevel accessLevel = 
						SourceCodeAccessLevel.getSourceCodeAccessLevel(scanParametersBean.getSourceCodeAccessLevel());
				VulnTypeStrategy typeStrategy =
						VulnTypeStrategy.getVulnTypeStrategy(scanParametersBean.getTypeMatchingStrategy());
				
				app.setFrameworkType(frameworkType.toString());
				app.setSourceCodeAccessLevel(accessLevel.toString());
				app.setVulnTypeStrategy(typeStrategy.toString());
				
				if (scanParametersBean.getSourceCodeUrl() != null && 
						scanParametersBean.getSourceCodeUrl().length() < Application.URL_LENGTH) {
					app.setRepositoryUrl(scanParametersBean.getSourceCodeUrl());
				}
				
				applicationDao.saveOrUpdate(app);
			}
		}
	}
}
