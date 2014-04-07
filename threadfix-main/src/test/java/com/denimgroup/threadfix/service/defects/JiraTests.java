package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

// TODO test some more edge cases
public class JiraTests implements TestConstants {

    // Setup methods; these should be modified for each type or genericized to work for all types

    public AbstractDefectTracker getTracker() {
        DefectTrackerType type = new DefectTrackerType();

        type.setName(DefectTrackerType.JIRA);

        AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(type);

        ((JiraDefectTracker) tracker).restUtils = new RestUtilsMock();

        return tracker;
    }

    public AbstractDefectTracker getConfiguredTracker() {
        AbstractDefectTracker tracker = getTracker();

        tracker.setUrl(JIRA_BASE_URL);
        tracker.setUsername(JIRA_USERNAME);
        tracker.setPassword(JIRA_PASSWORD);
        tracker.setProjectName(JIRA_VALID_PROJECT);

        return tracker;
    }

    // Generic Tests

    @Test
    public void testFactory() {
        AbstractDefectTracker jiraTracker = getTracker();

        assertTrue("Incorrect tracker returned from factory.", jiraTracker instanceof JiraDefectTracker);
    }

    @Test
    public void testHasValidUrl() {
        AbstractDefectTracker jiraTracker = getTracker();

        jiraTracker.setUrl(JIRA_BASE_URL);

        assertTrue("URL was supposed to be valid", jiraTracker.hasValidUrl());
    }

    @Test
    public void testInvalidUrl() {
        AbstractDefectTracker jiraTracker = getTracker();

        jiraTracker.setUrl("http://fake.com");

        assertFalse("Jira accepted fake url", jiraTracker.hasValidUrl());

        assertNotNull("Tracker error was null.", jiraTracker.getTrackerError());
    }

    @Test
    public void testHasValidCredentials() {
        AbstractDefectTracker jiraTracker = getTracker();

        jiraTracker.setUrl(JIRA_BASE_URL);
        jiraTracker.setUsername(JIRA_USERNAME);
        jiraTracker.setPassword(JIRA_PASSWORD);

        assertTrue("Credentials were supposed to be valid.", jiraTracker.hasValidCredentials());
    }

    @Test
    public void testGetProjectNames() {
        AbstractDefectTracker jiraTracker = getConfiguredTracker();

        List<String> projects = DefectUtils.getProductsFromString(jiraTracker.getProductNames());

        assertTrue("Length was supposed to be 3. It was " + projects.size(), projects.size() == 3);
    }

    @Test
    public void testHasValidProjectName() {
        AbstractDefectTracker jiraTracker = getConfiguredTracker();

        assertTrue("Project name was supposed to be valid.", jiraTracker.hasValidProjectName());
    }

    @Test
    public void testInvalidProjectName() {
        AbstractDefectTracker jiraTracker = getTracker();

        jiraTracker.setUrl(JIRA_BASE_URL);
        jiraTracker.setUsername(JIRA_USERNAME);
        jiraTracker.setPassword(JIRA_PASSWORD);
        jiraTracker.setProjectName("Dummy Project Name");

        assertFalse("Project name wasn't supposed to be valid.", jiraTracker.hasValidProjectName());
    }

    @Test
    public void testSubmissionParameters() {
        AbstractDefectTracker jiraTracker = getConfiguredTracker();

        ProjectMetadata metadata = jiraTracker.getProjectMetadata();

        // 1 is the default size ("-")
        int componentsSize = metadata.getComponents().size();
        assertEquals("Components size should have been 1. It was " + componentsSize, componentsSize, 1);

        int prioritiesSize = metadata.getPriorities().size();
        assertEquals("Priorities should have had 5 matches, but it had " + prioritiesSize, prioritiesSize, 5);
    }

    @Test
    public void testDefectCount() {
        AbstractDefectTracker jiraTracker = getConfiguredTracker();

        assertTrue("Expected 38 issues, got " + jiraTracker.getDefectList().size(), jiraTracker.getDefectList().size() == 38);
    }

    @Test
    public void testSubmitDefect() {
        AbstractDefectTracker jiraTracker = getConfiguredTracker();

        String nativeId = jiraTracker.createDefect(DefectUtils.getSampleVulnerabilities(),
                DefectUtils.getBasicMetadata(jiraTracker.getProjectMetadata()));

        assertTrue("Expected NCT-38 issues, got " + nativeId, "NCT-38".equals(nativeId));
    }

    @Test
    public void testDefectStatusUpdateCloseDefect() {
        AbstractDefectTracker jiraTracker = getConfiguredTracker();

        List<Defect> defects = DefectUtils.getDefectList("NCT-38");

        // This data structure was a bad idea
        Map<Defect, Boolean> resultMap = jiraTracker.getMultipleDefectStatus(defects);

        String status = defects.get(0).getStatus();

        assertTrue("Expected 'Closed', got '" + status + "'", "Closed".equals(status));

        assertFalse("Defect should have been closed.", resultMap.get(defects.get(0)));
    }

    @Test
    public void testDefectStatusUpdateNoChange() {
        AbstractDefectTracker jiraTracker = getConfiguredTracker();

        List<Defect> defects = DefectUtils.getDefectList("PDP-60");

        Map<Defect, Boolean> resultMap = jiraTracker.getMultipleDefectStatus(defects);

        String status = defects.get(0).getStatus();

        assertTrue("Expected 'Open', got '" + status + "'", "Open".equals(status));

        assertTrue("Defect should have been open.", resultMap.get(defects.get(0)));
    }

    // Jira-specific tests

    @Test
    public void testRestrictedReportField() {
        AbstractDefectTracker jiraTracker = getConfiguredTracker();

        // beautiful code
        ((RestUtilsMock) ((JiraDefectTracker) jiraTracker).restUtils).reporterRestricted = true;

        String nativeId = jiraTracker.createDefect(DefectUtils.getSampleVulnerabilities(),
                DefectUtils.getBasicMetadata(jiraTracker.getProjectMetadata()));

        assertTrue("Expected NCT-38 for the issue ID, got " + nativeId, "NCT-38".equals(nativeId));
    }

}
