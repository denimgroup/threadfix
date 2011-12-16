////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.FindingDao;
import com.denimgroup.threadfix.data.entities.Finding;

@Service
@Transactional(readOnly = true)
public class FindingServiceImpl implements FindingService {

	private FindingDao findingDao = null;

	@Autowired
	public FindingServiceImpl(FindingDao findingDao) {
		this.findingDao = findingDao;
	}

	@Override
	public List<Finding> loadAll() {
		return findingDao.retrieveAll();
	}

	@Override
	public Finding loadFinding(int findingId) {
		return findingDao.retrieveById(findingId);
	}
	
	@Override
	public List<String> loadSuggested(String hint, int appId) {
		return findingDao.retrieveByHint(hint, appId);
	}
	
	@Override
	public List<Finding> loadLatestStaticByAppAndUser(int appId, int userId) {
		return findingDao.retrieveLatestStaticByAppAndUser(appId, userId);
	}
	
	@Override
	public List<Finding> loadLatestDynamicByAppAndUser(int appId, int userId) {
		return findingDao.retrieveLatestDynamicByAppAndUser(appId, userId);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeFinding(Finding finding) {
		findingDao.saveOrUpdate(finding);
	}

}
