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
package com.denimgroup.threadfix.service.eventmodel.event;

import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.viewmodel.DefectMetadata;
import org.springframework.context.ApplicationEvent;

import java.util.List;

/**
 * Created by mac on 11/12/14.
 */
public class PreDefectSubmissionEvent extends ApplicationEvent {

    final AbstractDefectTracker defectTracker;
    final List<Vulnerability>   vulnerabilityList;
    final DefectMetadata        defectMetadata;

    // this could cause problems for the vuln list but it's much easier to ignore the broken java type system for now
    @SuppressWarnings("unchecked")
    public PreDefectSubmissionEvent(
            AbstractDefectTracker defectTracker,
            List vulnerabilityList,
            DefectMetadata defectMetadata) {
        super(defectMetadata);
        this.defectTracker = defectTracker;
        this.vulnerabilityList = vulnerabilityList;
        this.defectMetadata = defectMetadata;
    }

    public AbstractDefectTracker getDefectTracker() {
        return defectTracker;
    }

    public List getVulnerabilityList() {
        return vulnerabilityList;
    }

    public DefectMetadata getDefectMetadata() {
        return defectMetadata;
    }
}
