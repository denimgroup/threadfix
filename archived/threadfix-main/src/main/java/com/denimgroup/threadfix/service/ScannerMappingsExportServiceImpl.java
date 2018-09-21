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

import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by mac on 6/19/14.
 */
@Service
public class ScannerMappingsExportServiceImpl implements ScannerMappingsExportService {

    @Autowired
    private ChannelVulnerabilityDao channelVulnerabilityDao;

    @Override
    public boolean canUpdate() {
        return !channelVulnerabilityDao.loadAllUserCreated().isEmpty();
    }

    @Override
    public String getUserAddedMappingsInCSV() {
        List<ChannelVulnerability> channelVulnerabilityList =
                channelVulnerabilityDao.loadAllUserCreated();

        Map<String, StringBuilder> builderMap = new HashMap<>();

        for (ChannelVulnerability channelVulnerability : channelVulnerabilityList) {

            if (channelVulnerability != null &&
                    channelVulnerability.getGenericVulnerability() != null &&
                    channelVulnerability.getChannelType() != null &&
                    channelVulnerability.getChannelType().getName() != null) {

                String name = channelVulnerability.getChannelType().getName();

                if (!builderMap.containsKey(name)) {
                    builderMap.put(name, new StringBuilder(name).append("\n"));
                }

                builderMap.get(name)
                        .append(channelVulnerability.getName())
                        .append(',')
                        .append(channelVulnerability.getCode())
                        .append(',')
                        .append(channelVulnerability.getGenericVulnerability().getDisplayId())
                        .append("\n");
            }
        }

        StringBuilder completeMappingsBuilder = new StringBuilder();

        for (StringBuilder stringBuilder : builderMap.values()) {
            completeMappingsBuilder.append(stringBuilder);
        }

        try {
            return URLEncoder.encode(completeMappingsBuilder.toString(), "UTF-8").replaceAll("\\+", "%20");
        } catch (UnsupportedEncodingException e) {
            // we should make threadfix die at this point
            throw new RuntimeException("UTF-8 was not supported.", e);
        }

    }
}
