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
package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.service.defects.mock.BugzillaClientMock;
import com.denimgroup.threadfix.service.defects.util.DefectUtils;
import com.denimgroup.threadfix.service.defects.util.TestConstants;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by mac on 4/7/14.
 */
public class BugzillaTests implements TestConstants{

    public AbstractDefectTracker getTracker() {
        DefectTrackerType type = new DefectTrackerType();

        type.setName(DefectTrackerType.BUGZILLA);

        AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(type);

        // TODO mock the appropriate class
        ((BugzillaDefectTracker) tracker).bugzillaClient = new BugzillaClientMock();

        return tracker;
    }

    public AbstractDefectTracker getConfiguredTracker() {
        AbstractDefectTracker bugzillaTracker = getTracker();

        bugzillaTracker.setUrl(BUGZILLA_BASE_URL);
        bugzillaTracker.setUsername(BUGZILLA_USERNAME);
        bugzillaTracker.setPassword(BUGZILLA_PASSWORD);
        bugzillaTracker.setProjectName(BUGZILLA_PROJECT);

        return bugzillaTracker;
    }

    @Test
    public void testFactory() {
        AbstractDefectTracker bugzillaTracker = getTracker();

        assertTrue("Tracker should have been bugzilla but wasn't.", bugzillaTracker instanceof BugzillaDefectTracker);
    }

    @Test
    public void testHasValidURL() {
        AbstractDefectTracker bugzillaTracker = getTracker();

        bugzillaTracker.setUrl(BUGZILLA_BASE_URL);

        assertTrue("URL was supposed to be valid", bugzillaTracker.hasValidUrl());
    }

    @Test
    public void testInvalidCredentials() {
        AbstractDefectTracker bugzillaTracker = getTracker();

        bugzillaTracker.setUrl("http://fake.com");

        assertFalse("Bugzilla accepted a fake URL", bugzillaTracker.hasValidUrl());
    }

    @Test
    public void testHasValidCredentials() {
        AbstractDefectTracker bugzillaTracker = getTracker();

        bugzillaTracker.setUrl(BUGZILLA_BASE_URL);
        bugzillaTracker.setUsername(BUGZILLA_USERNAME);
        bugzillaTracker.setPassword(BUGZILLA_PASSWORD);

        assertTrue("Credentials were supposed to be valid.", bugzillaTracker.hasValidCredentials());
    }

    @Test
    public void testGetProjectName() {
        AbstractDefectTracker bugzillaTracker = getConfiguredTracker();

        List<String> projects = DefectUtils.getProductsFromString(bugzillaTracker.getProductNames());

        assertTrue("Expected 4 project, got " + projects.size(), projects.size() == 4);
    }

    @Test
    public void testHasValidProjectName() {
        AbstractDefectTracker bugzillaTracker = getConfiguredTracker();

        assertTrue("Project name was supposed to be valid.", bugzillaTracker.hasValidProjectName());
    }

    @Test
    public void testInvalidProjectName() {
        AbstractDefectTracker bugzillaTracker = getTracker();

        bugzillaTracker.setUrl(BUGZILLA_BASE_URL);
        bugzillaTracker.setUsername(BUGZILLA_USERNAME);
        bugzillaTracker.setPassword(BUGZILLA_PASSWORD);
        bugzillaTracker.setProjectName("Bad Project Name");

        assertFalse("Project name wasn't supposed to be valid.", bugzillaTracker.hasValidProjectName());
    }
}
