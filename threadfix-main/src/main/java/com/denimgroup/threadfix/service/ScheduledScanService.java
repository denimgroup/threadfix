////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.ScheduledScan;
import org.springframework.validation.BindingResult;

import java.util.List;

public interface ScheduledScanService {

    void validateScheduledDate(ScheduledScan scheduledScan, BindingResult result);
    int saveScheduledScan(Integer appId, ScheduledScan scheduledScan);
    String deleteScheduledScan(ScheduledScan scheduledScan);
    List<ScheduledScan> loadAllScheduledScan();
    ScheduledScan loadScheduledScanById(int scheduledScanId);
}
