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

import com.denimgroup.threadfix.annotations.ReportLocation;
import com.denimgroup.threadfix.data.dao.ReportDao;
import com.denimgroup.threadfix.data.entities.Report;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly=true)
public class ReportServiceImpl implements ReportService {

    private final SanitizedLogger log = new SanitizedLogger(ReportServiceImpl.class);

    @Autowired
    private ReportDao reportDao;

    private boolean initialized = false;

    public boolean isInitialized() {
        return initialized;
    }

    public void setInitialized(boolean initialized) {
        this.initialized = initialized;
    }

    @Override
    public List<Report> loadAll() {
        return reportDao.retrieveAll();
    }

    @Override
    public List<Report> loadAllAvailable() {
        return reportDao.retrieveAllAvailable();
    }

    @Override
    public List<Report> loadByIds(List<Integer> reportIds) {
        return reportDao.retrieveByIds(reportIds);
    }

    @Override
    public List<Report> loadAllNativeReports() {
        return reportDao.retrieveAllNativeReports();
    }

    @Override
    public List<Report> loadAllNonNativeReports() {
        return reportDao.retrieveAllNonNativeReports();
    }

    @Override
    public List<Report> loadAllNonNativeReportsByLocationType(ReportLocation location) {
        return reportDao.retrieveAllNonNativeReportsByLocationType(location);
    }

    @Override
    @Transactional(readOnly=false)
    public List<Report> loadByLocationType(ReportLocation location) {
        return reportDao.retrieveReportsByLocation(location);
    }

    @Override
    public Report load(int reportId) {
        return reportDao.retrieveById(reportId);
    }

    @Override
    public Report load(String name) {
        return reportDao.retrieveByName(name);
    }

    @Override
    @Transactional(readOnly = false)
    public void store(Report report) {
        reportDao.saveOrUpdate(report);
    }

    @Override
    @Transactional(readOnly = false)
    public void deleteById(int reportId) {
        log.info("Deleting Report with ID " + reportId);
        reportDao.delete(reportId);
    }

    @Override
    @Transactional(readOnly = false)
    public void delete(Report report) {
        log.info("Deleting Report '" + report.getShortName() +"'.");
        reportDao.delete(report);
    }

}
