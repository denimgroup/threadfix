////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.RealtimeMetaDataScanDao;
import com.denimgroup.threadfix.data.entities.RealtimeMetaDataScan;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import org.hibernate.SessionFactory;
import org.hibernate.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import java.util.List;


@Repository
public class HibernateRealtimeMetaDataScanDao implements RealtimeMetaDataScanDao {

    private SessionFactory sessionFactory;

    @Autowired
    public HibernateRealtimeMetaDataScanDao(final SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }


    @Override
    public RealtimeMetaDataScan reteriveByRemoteProviderApplicationID
            (final RemoteProviderApplication providerApplication) {
        return (RealtimeMetaDataScan) sessionFactory
                .getCurrentSession()
                .createQuery("from RealtimeMetaDataScan as realtime " +
                        "where realtime.remoteProviderApplication = :remoteProviderApplication  ")
                .setParameter("remoteProviderApplication", providerApplication).list().get(0);
    }

    @Override
    public Integer update(final RealtimeMetaDataScan realTimeMetadataScan) {
        Query query = sessionFactory.getCurrentSession().
                createQuery("update RealtimeMetaDataScan as metadata set metadata.numberTotalAuditedVulnerabilities = :numberTotalAuditedVulnerabilities," +
                        "metadata.application = :application," + "metadata.applicationChannel = :applicationChannel," +
                        "metadata.numberRealtimeCriticalVulnerabilities =:numberRealtimeCriticalVulnerabilities," +
                        "metadata.numberRealtimeHighVulnerabilities = :numberRealtimeHighVulnerabilities," +
                        "metadata.numberRealtimeCriticalAuditedVulnerabilities = :numberRealtimeCriticalAuditedVulnerabilities," +
                        "metadata.numberRealtimeHighAuditedVulnerabilities = :numberRealtimeHighAuditedVulnerabilities," +
                        "metadata.numberHighVulnerabilities = :numberHighVulnerabilities," +
                        "metadata.numberCriticalVulnerabilities = :numberCriticalVulnerabilities" +
                        " where metadata.remoteProviderApplication = :remoteProviderApplication");
        query.setParameter("numberTotalAuditedVulnerabilities", realTimeMetadataScan.getNumberTotalAuditedVulnerabilities());
        query.setParameter("remoteProviderApplication", realTimeMetadataScan.getRemoteProviderApplication());
        query.setParameter("application", realTimeMetadataScan.getApplication());
        query.setParameter("applicationChannel", realTimeMetadataScan.getApplicationChannel());
        query.setParameter("numberRealtimeCriticalVulnerabilities", realTimeMetadataScan.getNumberRealtimeCriticalAuditedVulnerabilities());
        query.setParameter("numberRealtimeHighVulnerabilities", realTimeMetadataScan.getNumberRealtimeHighVulnerabilities());
        query.setParameter("numberCriticalVulnerabilities", realTimeMetadataScan.getNumberCriticalVulnerabilities());
        query.setParameter("numberRealtimeCriticalAuditedVulnerabilities", realTimeMetadataScan.getNumberRealtimeCriticalAuditedVulnerabilities());
        query.setParameter("numberRealtimeHighAuditedVulnerabilities", realTimeMetadataScan.getNumberRealtimeHighAuditedVulnerabilities());
        query.setParameter("numberHighVulnerabilities", realTimeMetadataScan.getNumberHighVulnerabilities());
        return query.executeUpdate();
    }

    @Override
    public RealtimeMetaDataScan reteriveByApplicationChannelID(final ApplicationChannel channel) {
        return (RealtimeMetaDataScan) sessionFactory
                .getCurrentSession()
                .createQuery("from RealtimeMetaDataScan as realtime " +
                        "where realtime.applicationChannel = :applicationChannel  ")
                .setParameter("applicationChannel", channel).list().get(0);

    }

    @Override
    public void delete(final RealtimeMetaDataScan realtimeMetaDataScan) {
        sessionFactory.getCurrentSession().delete(realtimeMetaDataScan);
    }

    @Override
    public RealtimeMetaDataScan retrieveById(final int id) {
        return null;
    }

    @Override
    public List<RealtimeMetaDataScan> retrieveAllActive() {
        return null;
    }

    @Override
    public List<RealtimeMetaDataScan> retrieveAll() {
        List<RealtimeMetaDataScan> metaDataScans = sessionFactory.getCurrentSession()
                .createQuery("from RealtimeMetaDataScan ").list();
        return metaDataScans;
    }

    @Override
    public void saveOrUpdate(final RealtimeMetaDataScan object) {

        if (object != null) {
            sessionFactory.getCurrentSession().saveOrUpdate(object);
        }
    }
}
