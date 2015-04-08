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
import com.denimgroup.threadfix.data.entities.Report;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * @author zabdisubhan
 *
 */
public interface ReportService {

    boolean isInitialized();

    void setInitialized(boolean initialized);

    /**
     * @return List<Report>
     */
    List<Report> loadAll();

   /**
     * @return List<Report>
     */
    List<Report> loadAllAvailable();

    /**
     * @return List<Report>
     */
    List<Report> loadByIds(List<Integer> reportIds);

    /**
     * @return List<Report>
     */
    List<Report> loadAllNativeReports();

    /**
     * @return List<Report>
     */
    List<Report> loadAllNonNativeReports();

    /**
     * @return List<Report>
     */
    @Transactional
    List<Report> loadByLocationType(ReportLocation location);

    /**
     * @param reportId
     * @return Report
     */
    Report load(int reportId);

    /**
     * @param shortName
     * @return Report
     */
    Report load(String shortName);

    /**
     * @param report
     */
    void store(Report report);

    /**
     * @param report
     */
    void delete(Report report);

    /**
     * @param reportId
     */
    void deleteById(int reportId);

}
