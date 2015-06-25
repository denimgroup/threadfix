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

import com.denimgroup.threadfix.data.dao.GenericNamedObjectDao;
import com.denimgroup.threadfix.data.dao.GenericSeverityDao;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GenericSeverityServiceImpl
		extends AbstractNamedObjectService<GenericSeverity>
		implements GenericSeverityService {

	@Autowired
	GenericSeverityDao genericSeverityDao;

	@Override
	public List<GenericSeverity> loadAll() {
		return getDao().retrieveAll();
	}

	@Override
	public boolean canSetCustomNameTo(int genericSeverityId, String text) {
		if ("".equals(text)) {
			return true; // it's ok to clear the custom text
		}

		List<GenericSeverity> genericSeverities = genericSeverityDao.retrieveAllWithCustomName(text);

		for (GenericSeverity genericSeverity : genericSeverities) {
			if (text.equals(genericSeverity.getCustomName()) && genericSeverity.getId() != genericSeverityId) {
				return false; // a different severity has this name
			}
		}

		return true;
	}

	@Override
	public GenericNamedObjectDao<GenericSeverity> getDao() {
		return genericSeverityDao;
	}
}
