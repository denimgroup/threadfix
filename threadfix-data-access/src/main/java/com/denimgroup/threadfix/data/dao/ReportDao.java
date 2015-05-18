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

package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.annotations.ReportLocation;
import com.denimgroup.threadfix.data.entities.Report;

import java.util.List;

/**
 * @author zabdisubhan
 */

public interface ReportDao extends GenericNamedObjectDao<Report> {

    List<Report> retrieveByIds(List<Integer> reportIds);

    List<Report> retrieveAllAvailable();

    List<Report> retrieveAllNativeReports();

    List<Report> retrieveAllNonNativeReports();

    List<Report> retrieveReportsByLocation(ReportLocation location);

    void delete(Report report);

    void delete(Integer reportId);

    List<Report> retrieveAllNonNativeReportsByLocationType(ReportLocation location);
}