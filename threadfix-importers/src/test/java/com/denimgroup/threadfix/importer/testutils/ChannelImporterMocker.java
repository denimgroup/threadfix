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

package com.denimgroup.threadfix.importer.testutils;

import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;

import java.util.List;

/**
 * Created by mac on 2/4/14.
 */
public class ChannelImporterMocker {

    /**
     *   @Autowired
         protected ChannelVulnerabilityDao channelVulnerabilityDao;
         @Autowired
         protected ChannelSeverityDao channelSeverityDao;
         @Autowired
         protected ChannelTypeDao channelTypeDao;
         @Autowired
         protected GenericVulnerabilityDao genericVulnerabilityDao;
     * @param importer
     */
    public static void mockIt(ChannelImporter importer) {
        ChannelVulnerabilityDao channelVulnerabilityDao = new ChannelVulnerabilityDao() {
            @Override
            public ChannelVulnerability retrieveByCode(ChannelType channelType, String code) {
                ChannelVulnerability vuln = new ChannelVulnerability();

                vuln.setCode(code);
                vuln.setChannelType(channelType);

                return vuln;
            }

            @Override
            public ChannelVulnerability retrieveByName(ChannelType channelType, String name) {
                ChannelVulnerability vuln = new ChannelVulnerability();

                vuln.setName(name);
                vuln.setChannelType(channelType);

                return vuln;
            }

            @Override
            public boolean hasMappings(int id) {
                return false;
            }

            @Override
            public ChannelVulnerability retrieveById(int id) {
                return null;
            }

            @Override
            public List<ChannelVulnerability> retrieveSuggested(String prefix) {
                return null;
            }

            @Override
            public void saveOrUpdate(ChannelVulnerability channelVulnerability) {

            }

            @Override
            public boolean isValidManualName(String name) {
                return false;
            }

            @Override
            public List<ChannelVulnerability> retrieveAllManual() {
                return null;
            }
        };

    }


}
