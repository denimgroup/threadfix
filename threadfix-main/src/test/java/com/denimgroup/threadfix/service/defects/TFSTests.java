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
import com.denimgroup.threadfix.service.defects.mock.TFSClientMock;
import com.denimgroup.threadfix.service.defects.util.DefectUtils;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;
import org.junit.Ignore;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static com.denimgroup.threadfix.service.defects.util.TestConstants.*;

/**
 * Created by mac on 4/7/14.
 */
public class TFSTests {

    public AbstractDefectTracker getTracker() {
        DefectTrackerType type = new DefectTrackerType();

        type.setName(DefectTrackerType.MICROSOFT_TFS);

        AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(type);

        // TODO mock the appropriate class
        ((TFSDefectTracker) tracker).client = new TFSClientMock();

        return tracker;
    }

    public AbstractDefectTracker getConfiguredTracker() {
        AbstractDefectTracker tfsTracker = getTracker();

        tfsTracker.setUrl(TFS_BASE_URL);
        tfsTracker.setUsername(TFS_USERNAME);
        tfsTracker.setPassword(TFS_PASSWORD);
        tfsTracker.setProjectName(TFS_PROJECT);

        return tfsTracker;
    }

    @Test
    public void testFactory() {
        AbstractDefectTracker tracker = getTracker();

        assertTrue("Tracker should have been HPQC but wasn't.", tracker instanceof TFSDefectTracker);
    }

    @Test
    public void testHasValidURL() {
        AbstractDefectTracker tfsTracker = getTracker();

        tfsTracker.setUrl(TFS_BASE_URL);

        assertTrue("URL was supposed to be valid", tfsTracker.hasValidUrl());
    }

    @Test
    public void testInvalidURL() {
        AbstractDefectTracker tfsTracker = getTracker();

        tfsTracker.setUrl("http://fake.com");

        assertFalse("TFS accepted a fake URL", tfsTracker.hasValidUrl());
    }

    @Test
    public void testHasValidCredentials() {
        AbstractDefectTracker tfsTracker = getConfiguredTracker();

        assertTrue("Credentials were supposed to be valid.", tfsTracker.hasValidCredentials());
    }

    @Test
    public void testHasInvalidCredentials() {
        AbstractDefectTracker tfsTracker = getTracker();

        tfsTracker.setUrl("http://fake.com");
        tfsTracker.setUsername("badUsername");
        tfsTracker.setPassword("badPassword");

        assertTrue("Credentials were supposed to be invalid.", !tfsTracker.hasValidCredentials());
    }

    @Test
    public void testGetProjectName() {
        AbstractDefectTracker tfsTracker = getConfiguredTracker();

        List<String> projects = DefectUtils.getProductsFromString(tfsTracker.getProductNames());

        assertTrue("Expected 5 projects, got " + projects.size(), projects.size() == 5);
    }

    @Test
    public void testHasValidProjectName() {
        AbstractDefectTracker tfsTracker = getConfiguredTracker();

        assertTrue("Project name was supposed to be valid.", tfsTracker.hasValidProjectName());
    }

    @Test
    public void testHasInvalidProjectName() {
        AbstractDefectTracker tfsTracker = getConfiguredTracker();

        tfsTracker.setProjectName("Fake Project");

        assertFalse("Project name wasn't supposed to be valid.", tfsTracker.hasValidProjectName());
    }

    @Test
    public void testSubmissionParameters() {
        AbstractDefectTracker tfsTracker = getConfiguredTracker();

        ProjectMetadata metadata = tfsTracker.getProjectMetadata();

        int statusSize = metadata.getStatuses().size();
        assertEquals("Status should have 1 match, but had " + statusSize, statusSize, 1);

        int prioritySize = metadata.getPriorities().size();
        assertEquals("Priorities should have X matches, but had " + prioritySize, prioritySize, 1);
    }

    @Test
    public void testDefectCount() {
        AbstractDefectTracker tfsTracker = getConfiguredTracker();

        int defectCount = tfsTracker.getDefectList().size();
        assertTrue("Expected 3 number of issues, got " + defectCount, defectCount == 3);
    }

    //TODO Wait for TFS to work in order to get 'createDefect' to work properly
    @Ignore
    @Test
    public void testSubmitDefect() {
        AbstractDefectTracker tfsTracker = getConfiguredTracker();

        String nativeId = tfsTracker.createDefect(DefectUtils.getSampleVulnerabilities(),
                DefectUtils.getBasicMetadata(tfsTracker.getProjectMetadata()));

        assertTrue("Expected ID to be Test, but was " + nativeId, "Test".equals(nativeId));
    }

    //TODO Wait for TFS to work in order to get 'createDefect' to work properly
    @Ignore
    @Test
    public void testDefectStatusUpdateCloseDefect() {
        AbstractDefectTracker tfsTracker = getConfiguredTracker();

        List<Defect> defects = DefectUtils.getDefectList("1");

        Map<Defect, Boolean> resultMap = tfsTracker.getMultipleDefectStatus(defects);

        String status = defects.get(0).getStatus();

    }

    //TODO Wait for TFS to work in order to get 'createDefect' to work properly
    @Ignore
    @Test
    public void testDefectStatusUpdateNoChange() {
        AbstractDefectTracker tfsTracker = getConfiguredTracker();

        List<Defect> defects = DefectUtils.getDefectList("2");

        Map<Defect, Boolean> resultMap = tfsTracker.getMultipleDefectStatus(defects);

    }
}
