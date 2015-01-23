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

import com.denimgroup.threadfix.data.dao.GraphConfigDao;
import com.denimgroup.threadfix.data.entities.GraphConfig;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Map;

@Repository
public class HibernateGraphConfigDao implements GraphConfigDao {

    private SessionFactory sessionFactory;

    @Autowired
    public HibernateGraphConfigDao(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<GraphConfig> getScannerNames() {
        return  sessionFactory.getCurrentSession().createCriteria(GraphConfig.class).list();
    }

    @SuppressWarnings("unchecked")
    @Override
    public Map<String, Object> getChecked(){
        return (Map<String, Object>) sessionFactory.getCurrentSession().createQuery(
                "select new map( graphConfig.id as id, select graphConfig.criticalVulns as criticalVulns" +
                        " from GraphConfig graphConfig where graphConfig.name = :names")
                .setParameterList("names", getScannerNames())
                .uniqueResult();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<GraphConfig> retrieveAll() {
        return null;
    }

    @Override
    @SuppressWarnings("unchecked")
    public void loadTable(String scannerName){
        sessionFactory.getCurrentSession()
                .createSQLQuery("insert into graphConfig as GraphConfig (graphConfig.auditable, graphConfig.criticalvulns, graphConfig.highvulns, graphConfig.mediumvulns, graphConfig.lowvulns, graphConfig.infovulns, graphConfig.name) VALUES (false, false, false, false, false, false, 'Nessus')");
                //.setString("names", scannerName);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<GraphConfig> retrieveAllActive() {
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    @Transactional(readOnly = false) // used to be true
    public GraphConfig retrieveById(int id) {
        return null;
    }


    @SuppressWarnings("unchecked")
    @Override
    public void updateScanners(GraphConfig graphConfig) {
        sessionFactory.getCurrentSession().saveOrUpdate(graphConfig);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void saveOrUpdate(GraphConfig graphConfig) {
        sessionFactory.getCurrentSession().saveOrUpdate(graphConfig);
    }
}
