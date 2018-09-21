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
package com.denimgroup.threadfix.cli;

import com.denimgroup.threadfix.VulnerabilityInfo;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.remote.response.RestResponse;

import java.util.Date;
import java.util.List;

/**
 * Created by mac on 5/22/14.
 */
public class ThreadFixRestClientStub extends ThreadFixRestClientImpl {

    List<Integer> genericVulnerabilityIds, teamIds, applicationIds, genericSeverityValues;
    List<String> scannerNames;
    String parameter, path;
    Date startDate, endDate;
    Boolean showOpen, showClosed, showFalsePositive, showHidden,
            showDefectPresent, showDefectNotPresent, showDefectOpen, showDefectClosed,
            showInconsistentClosedDefectNeedsScan, showInconsistentClosedDefectOpenInScan,
            showInconsistentOpenDefect;
    Integer numberMerged, numberVulnerabilities;

    @Override
    public RestResponse<VulnerabilityInfo[]> searchVulnerabilities(List<Integer> genericVulnerabilityIds,
               List<Integer> teamIds, List<Integer> applicationIds, List<String> scannerNames,
               List<Integer> genericSeverityValues, Integer numberVulnerabilities, String parameter, String path,
               Date startDate, Date endDate, Boolean showOpen, Boolean showClosed, Boolean showFalsePositive,
               Boolean showHidden, Integer numberMerged,  Boolean showDefectPresent, Boolean showDefectNotPresent,
               Boolean showDefectOpen, Boolean showDefectClosed, Boolean showInconsistentClosedDefectNeedsScan,
               Boolean showInconsistentClosedDefectOpenInScan, Boolean showInconsistentOpenDefect) {
        this.genericVulnerabilityIds = genericVulnerabilityIds;
        this.teamIds = teamIds;
        this.applicationIds = applicationIds;
        this.scannerNames = scannerNames;
        this.genericSeverityValues = genericSeverityValues;
        this.numberVulnerabilities = numberVulnerabilities;
        this.parameter = parameter;
        this.path = path;
        this.startDate = startDate;
        this.endDate = endDate;
        this.showOpen = showOpen;
        this.showClosed = showClosed;
        this.showFalsePositive = showFalsePositive;
        this.showHidden = showHidden;
        this.numberMerged = numberMerged;
        this.showDefectPresent = showDefectPresent;
        this.showDefectNotPresent = showDefectNotPresent;
        this.showDefectOpen = showDefectOpen;
        this.showDefectClosed = showDefectClosed;
        this.showInconsistentClosedDefectNeedsScan = showInconsistentClosedDefectNeedsScan;
        this.showInconsistentClosedDefectOpenInScan = showInconsistentClosedDefectOpenInScan;
        this.showInconsistentOpenDefect = showInconsistentOpenDefect;
        return null;
    }

}

