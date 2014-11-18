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

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.service.defects.mock.BugzillaClientMock;
import com.denimgroup.threadfix.service.defects.util.DefectUtils;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static com.denimgroup.threadfix.service.defects.util.TestConstants.*;

/**
 * Created by mac on 4/7/14.
 */
public class BugzillaTests {

    public AbstractDefectTracker getTracker() {
        DefectTrackerType type = new DefectTrackerType();

        type.setName(DefectTrackerType.BUGZILLA);

        AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(type);

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
    public void testInvalidUrl() {
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
    public void testHasInvalidCredentials() {
        AbstractDefectTracker bugzillaTracker = getTracker();

        bugzillaTracker.setUrl("http://fakeurl.com");
        bugzillaTracker.setUsername("usernameWrong");
        bugzillaTracker.setPassword("passwordWrong");

        assertTrue("Credentials were supposed to be valid.", !bugzillaTracker.hasValidCredentials());
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
        AbstractDefectTracker bugzillaTracker = getConfiguredTracker();

        bugzillaTracker.setProjectName("Bad Project Name");

        assertFalse("Project name wasn't supposed to be valid.", bugzillaTracker.hasValidProjectName());
    }

    @Test
    public void testSubmissionParameters() {
        AbstractDefectTracker bugzillaTracker = getConfiguredTracker();

        ProjectMetadata metadata = bugzillaTracker.getProjectMetadata();

        int severitySize = metadata.getSeverities().size();
        assertEquals("Severities should have had 7 matches, but had " + severitySize, severitySize, 7);

        int statusSize = metadata.getStatuses().size();
        assertEquals("Status should have had 4 matches, but had " + statusSize, statusSize, 4);

        int prioritySize = metadata.getPriorities().size();
        assertEquals("Priorities should have had 6 matches, but had " + prioritySize, prioritySize, 6);

        int versionSize = metadata.getVersions().size();
        assertEquals("Version size should have been 1, but was " + versionSize, versionSize, 1);

        int componentSize = metadata.getComponents().size();
        assertEquals("Components size should have been 1, but was " + componentSize, componentSize, 1);

    }

    @Test
    public void testDefectCount() {
        AbstractDefectTracker bugzillaTracker = getConfiguredTracker();

        int defectCount = bugzillaTracker.getDefectList().size();
        assertTrue("Expected 4 number of issues, got " + defectCount, defectCount == 4 );
    }

    @Test
    public void testSubmitDefect() {
        AbstractDefectTracker bugzillaTracker = getConfiguredTracker();

        String nativeId = bugzillaTracker.createDefect(DefectUtils.getSampleVulnerabilities(),
                DefectUtils.getBasicMetadata(bugzillaTracker.getProjectMetadata()));

        assertTrue("Expected ID to be 110 but was " + nativeId, "110".equals(nativeId));
    }

    @Test
    public void testDefectStatusUpdateCloseDefect() {
        AbstractDefectTracker bugzillaTracker = getConfiguredTracker();

        List<Defect> defects = DefectUtils.getDefectList("1");

        Map<Defect, Boolean> resultMap = bugzillaTracker.getMultipleDefectStatus(defects);

        String status = defects.get(0).getStatus();

        assertTrue("Expected 'RESOLVED', got '" + status + "'", "RESOLVED".equals(status));

        assertFalse("Defect should have been closed.", resultMap.get(defects.get(0)));
    }

    @Test
    public void testDefectStatusUpdateNoChange() {
        AbstractDefectTracker bugzillaTracker = getConfiguredTracker();

        List<Defect> defects = DefectUtils.getDefectList("2");

        Map<Defect, Boolean> resultMap = bugzillaTracker.getMultipleDefectStatus(defects);

        String status = defects.get(0).getStatus();

        assertTrue("Expected 'CONFIRMED', got '" + status + "'", "CONFIRMED".equals(status));

        assertTrue("Defect should have been open.", resultMap.get(defects.get(0)));
    }

}
