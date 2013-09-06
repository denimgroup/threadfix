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

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.GenericSeverityDao;
import com.denimgroup.threadfix.data.entities.GenericSeverity;

@Service
public class GenericSeverityServiceImpl implements GenericSeverityService {

	GenericSeverityDao genericSeverityDao = null;
	
	@Autowired
	public GenericSeverityServiceImpl(GenericSeverityDao genericSeverityDao ) {
		this.genericSeverityDao = genericSeverityDao;
	}
	
	@Override
	public List<GenericSeverity> loadAll() {
		return genericSeverityDao.retrieveAll();
	}

	@Override
	public GenericSeverity load(String name) {
		return genericSeverityDao.retrieveByName(name);
	}

	@Override
	public GenericSeverity load(int id) {
		return genericSeverityDao.retrieveById(id);
	}
}
