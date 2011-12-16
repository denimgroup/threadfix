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

import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;

@Service
@Transactional(readOnly = true)
public class OrganizationServiceImpl implements OrganizationService {

	private OrganizationDao organizationDao = null;
	private ApplicationDao applicationDao = null;

	@Autowired
	public OrganizationServiceImpl(OrganizationDao organizationDao, ApplicationDao applicationDao) {
		this.organizationDao = organizationDao;
		this.applicationDao = applicationDao;
	}

	@Override
	public List<Organization> loadAll() {
		return organizationDao.retrieveAll();
	}

	@Override
	public List<Organization> loadAllActive() {
		return organizationDao.retrieveAllActive();
	}

	@Override
	public List<Organization> loadAllNoOrder() {
		return organizationDao.retrieveAllNoOrder();
	}

	@Override
	public Organization loadOrganization(int organizationId) {
		return organizationDao.retrieveById(organizationId);
	}

	@Override
	public Organization loadOrganization(String name) {
		return organizationDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeOrganization(Organization organization) {
		organizationDao.saveOrUpdate(organization);
	}

	@Override
	@Transactional(readOnly = false)
	public void deleteById(int organizationId) {
		organizationDao.deleteById(organizationId);
	}

	@Override
	@Transactional(readOnly = false)
	public void deactivateOrganization(Organization organization) {
		organization.setActive(false);
		organization.setModifiedDate(new Date());
		
		if (organization.getActiveApplications() != null) {
			for (Application app : organization.getActiveApplications()) {
				app.setActive(false);
				app.setModifiedDate(new Date());
				applicationDao.saveOrUpdate(app);
			}
		}
		
		organizationDao.saveOrUpdate(organization);
	}

}
