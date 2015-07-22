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
package com.denimgroup.threadfix.data.dao.hibernate;

import java.util.List;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;

@Repository
public class HibernateChannelSeverityDao implements ChannelSeverityDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateChannelSeverityDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<ChannelSeverity> retrieveByChannel(ChannelType channelType) {
		return sessionFactory
				.getCurrentSession()
				.createQuery(
						"from ChannelSeverity cs where cs.channelType = :channelTypeId")
				.setInteger("channelTypeId", channelType.getId()).list();
	}

	@Override
	public ChannelSeverity retrieveByCode(ChannelType channelType, String code) {
		return (ChannelSeverity) sessionFactory
				.getCurrentSession()
				.createQuery(
						"from ChannelSeverity cs where cs.code = :code "
								+ "and cs.channelType = :channelTypeId")
				.setString("code", code)
				.setInteger("channelTypeId", channelType.getId())
				.uniqueResult();
	}

	@Override
	public ChannelSeverity retrieveById(int id) {
		return (ChannelSeverity) sessionFactory.getCurrentSession().get(
				ChannelSeverity.class, id);
	}

	@Override
	public void saveOrUpdate(ChannelSeverity channelSeverity) {
		sessionFactory.getCurrentSession().saveOrUpdate(channelSeverity.getSeverityMap());
		sessionFactory.getCurrentSession().saveOrUpdate(channelSeverity);
	}

	@Override
	public void updateExistingVulns(List<Integer> channelSeverityIds) {

		for (Integer channelSeverityId: channelSeverityIds) {
			ChannelSeverity channelSeverity = retrieveById(channelSeverityId);
			if (channelSeverity == null)
				continue;

			List list = sessionFactory.getCurrentSession().createQuery(
					"select finding.vulnerability.id from Finding finding where finding.channelSeverity.id = :channelSeverityId and finding.firstFindingForVuln = true")
					.setParameter("channelSeverityId", channelSeverityId)
					.list();

			if (!list.isEmpty()) {
				sessionFactory.getCurrentSession().createQuery(
						"update Vulnerability vulnerability set genericSeverity = :genericSeverity where id in (:vulnIds)")
						.setParameterList("vulnIds", list)
						.setParameter("genericSeverity", channelSeverity.getSeverityMap().getGenericSeverity())
						.executeUpdate();

				sessionFactory.getCurrentSession().createQuery(
						"update StatisticsCounter counter set currentGenericSeverityId = :genericSeverityId where vulnerabilityId in (:vulnIds)")
						.setParameterList("vulnIds", list)
						.setParameter("genericSeverityId", channelSeverity.getSeverityMap().getGenericSeverity().getId())
						.executeUpdate();
			}
		}
	}
}
