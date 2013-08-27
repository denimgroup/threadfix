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

import com.denimgroup.threadfix.data.dao.SeverityFilterDao;
import com.denimgroup.threadfix.data.entities.SeverityFilter;

@Service
public class SeverityFilterServiceImpl implements SeverityFilterService {

	public SeverityFilterDao severityFilterDao = null;

	@Autowired
	public SeverityFilterServiceImpl(SeverityFilterDao severityFilterDao) {
		this.severityFilterDao = severityFilterDao;
	}

	@Override
	@Transactional
	public void save(SeverityFilter severityFilter) {
		severityFilterDao.saveOrUpdate(severityFilter);
	}

	@Override
	public SeverityFilter loadGlobal() {
		return severityFilterDao.retrieveGlobal();
	}

	@Override
	public SeverityFilter loadTeam(int orgId) {
		return severityFilterDao.retrieveTeam(orgId);
	}

	@Override
	public SeverityFilter loadApplication(int appId) {
		return severityFilterDao.retrieveApplication(appId);
	}

	@Override
	public void clean(SeverityFilter severityFilter, int teamId, int appId) {
		if (severityFilter != null && !severityFilter.getEnabled()) {
			severityFilter.setFilters(getParentFilter(teamId, appId));
		}
	}
	
	@Override
	public SeverityFilter getParentFilter(int teamId, int appId) {
		SeverityFilter returnFilter = new SeverityFilter();
		
		// if teamId == -1 and appId == -1 then we're finding the parent of global, which is just the default SeverityFilter
		if (teamId != -1 && appId == -1) {
			
			// if we're finding the parent of a team filter, let's use global settings if present
			SeverityFilter globalFilter = loadGlobal();
			if (globalFilter != null && globalFilter.getEnabled()) {
				returnFilter = globalFilter;
			}
			
		} else if (teamId != -1 && appId != -1) {
			SeverityFilter targetFilter = loadTeam(teamId);
			
			if (targetFilter != null && targetFilter.getEnabled()) {
				// this is an app level filter and there are team settings, so let's use those
				returnFilter = targetFilter;
				
			} else {
				
				// there are no team settings, so let's look at global
				targetFilter = loadGlobal();
				
				if (targetFilter == null || !targetFilter.getEnabled()) {
					// this is a team level filter and there are team level settings, so let's use those
					returnFilter = targetFilter;
				}
			}
		}

		return returnFilter;
	}

}
