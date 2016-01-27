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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.ScanResultFilterDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.ScanResultFilter;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly = false)
public class ScanResultFilterServiceImpl implements ScanResultFilterService{

    protected final SanitizedLogger log = new SanitizedLogger(ScanResultFilterServiceImpl.class);

    @Autowired
    private ScanResultFilterDao scanResultFilterDao;

    @Autowired
    private FindingService findingService;

    @Autowired
    private VulnerabilityFilterService vulnerabilityFilterService;

    @Override
    public List<ScanResultFilter> loadAll() {
        return scanResultFilterDao.retrieveAll();
    }

    @Override
    public void storeAndApplyFilter(ScanResultFilter scanResultFilter) {
        storeAndApplyFilter(scanResultFilter, null, null);
    }

    @Override
    public void storeAndApplyFilter(ScanResultFilter scanResultFilter, GenericSeverity previousGenericSeverity, ChannelType previousChannelType) {
        scanResultFilterDao.saveOrUpdate(scanResultFilter);
        vulnerabilityFilterService.updateAllVulnerabilities();
    }

    private void unFilterFindings(GenericSeverity genericSeverity, ChannelType channelType){
        List<Finding> findingsToUnFilter = findingService.loadByGenericSeverityAndChannelType(genericSeverity, channelType);

        if(findingsToUnFilter != null && !findingsToUnFilter.isEmpty()){
            for(Finding finding : findingsToUnFilter){
                finding.setHidden(false);
                findingService.storeFinding(finding);
            }
        }
    }

    @Override
    public ScanResultFilter loadById(int scanResultFilterId) {
        return scanResultFilterDao.retrieveById(scanResultFilterId);
    }

    @Override
    public void delete(ScanResultFilter scanResultFilter) {
        unFilterFindings(scanResultFilter.getGenericSeverity(), scanResultFilter.getChannelType());
        scanResultFilterDao.delete(scanResultFilter);
        vulnerabilityFilterService.updateAllVulnerabilities();
    }

    @Override
    public List<GenericSeverity> loadFilteredSeveritiesForChannelType(ChannelType channelType) {
        return scanResultFilterDao.loadFilteredSeveritiesForChannelType(channelType);
    }

    @Override
    public ScanResultFilter loadByChannelTypeAndSeverity(ChannelType channelType, GenericSeverity genericSeverity) {
        return scanResultFilterDao.loadByChannelTypeAndSeverity(channelType, genericSeverity);
    }
}
