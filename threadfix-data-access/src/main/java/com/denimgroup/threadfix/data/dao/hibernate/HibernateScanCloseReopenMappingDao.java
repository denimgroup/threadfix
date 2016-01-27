////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.ScanCloseReopenMappingDao;
import com.denimgroup.threadfix.data.entities.ScanCloseVulnerabilityMap;
import com.denimgroup.threadfix.data.entities.ScanReopenVulnerabilityMap;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Created by mcollins on 2/9/15.
 */
@Repository
public class HibernateScanCloseReopenMappingDao implements ScanCloseReopenMappingDao {

    @Autowired
    SessionFactory sessionFactory;

    @Override
    public void delete(ScanCloseVulnerabilityMap map) {

        if (map.getScan() != null &&
                map.getScan().getScanCloseVulnerabilityMaps() != null) {
            map.getScan().getScanCloseVulnerabilityMaps().remove(map);
        }

        if (map.getVulnerability() != null &&
                map.getVulnerability().getScanCloseVulnerabilityMaps() != null) {
            map.getVulnerability().getScanCloseVulnerabilityMaps().remove(map);
        }

        map.setScan(null);
        map.setVulnerability(null);

        sessionFactory.getCurrentSession().delete(map);
    }

    @Override
    public void delete(ScanReopenVulnerabilityMap map) {
        if (map.getScan() != null &&
                map.getScan().getScanReopenVulnerabilityMaps() != null) {
            map.getScan().getScanReopenVulnerabilityMaps().remove(map);
        }

        if (map.getVulnerability() != null &&
                map.getVulnerability().getScanReopenVulnerabilityMaps() != null) {
            map.getVulnerability().getScanReopenVulnerabilityMaps().remove(map);
        }

        map.setScan(null);
        map.setVulnerability(null);

        sessionFactory.getCurrentSession().delete(map);
    }
}
