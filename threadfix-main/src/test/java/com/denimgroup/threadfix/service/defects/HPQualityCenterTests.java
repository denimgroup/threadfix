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
package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class HPQualityCenterTests {

    public AbstractDefectTracker getTracker() {
        DefectTrackerType type = new DefectTrackerType();

        type.setName(DefectTrackerType.HP_QUALITYCENTER);

        AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(type);

        // TODO mock the appropriate class
        //((JiraDefectTracker) tracker).restUtils = new RestUtilsMock();

        return tracker;
    }

    @Test
    public void testFactory() {
        AbstractDefectTracker tracker = getTracker();

        assertTrue("Tracker should have been HPQC but wasn't.", tracker instanceof HPQualityCenterDefectTracker);
    }

}
