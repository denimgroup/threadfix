package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class JiraTests implements TestConstants {

    public AbstractDefectTracker getTracker(String trackerName) {
        DefectTrackerType type = new DefectTrackerType();

        type.setName(trackerName);

        AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(type);

        ((JiraDefectTracker) tracker).restUtils = new RestUtilsMock();

        return tracker;
    }

    @Test
    public void testFactory() {
        AbstractDefectTracker jiraTracker = getTracker(DefectTrackerType.JIRA);

        assertTrue("Incorrect tracker returned from factory.", jiraTracker instanceof JiraDefectTracker);
    }

    @Test
    public void testHasValidUrl() {
        AbstractDefectTracker jiraTracker = getTracker(DefectTrackerType.JIRA);

        jiraTracker.setUrl(JIRA_BASE_URL);

        assertTrue("URL was supposed to be valid", jiraTracker.hasValidUrl());
    }

    @Test
    public void testInvalidUrl() {
        AbstractDefectTracker jiraTracker = getTracker(DefectTrackerType.JIRA);

        jiraTracker.setUrl("http://fake.com");

        assertFalse("Jira accepted fake url", jiraTracker.hasValidUrl());
    }

    @Test
    public void testHasValidCredentials() {
        AbstractDefectTracker jiraTracker = getTracker(DefectTrackerType.JIRA);

        jiraTracker.setUrl(JIRA_BASE_URL);
        jiraTracker.setUsername(JIRA_USERNAME);
        jiraTracker.setPassword(JIRA_PASSWORD);

        assertTrue("Credentials were supposed to be valid.", jiraTracker.hasValidCredentials());
    }

    @Test
    public void testHasValidProjectName() {
        AbstractDefectTracker jiraTracker = getTracker(DefectTrackerType.JIRA);

        jiraTracker.setUrl(JIRA_BASE_URL);
        jiraTracker.setUsername(JIRA_USERNAME);
        jiraTracker.setPassword(JIRA_PASSWORD);
        jiraTracker.setProjectName(JIRA_VALID_PROJECT);

        assertTrue("Project name was supposed to be valid.", jiraTracker.hasValidProjectName());
    }

    @Test
    public void testInvalidProjectName() {
        AbstractDefectTracker jiraTracker = getTracker(DefectTrackerType.JIRA);

        jiraTracker.setUrl(JIRA_BASE_URL);
        jiraTracker.setUsername(JIRA_USERNAME);
        jiraTracker.setPassword(JIRA_PASSWORD);
        jiraTracker.setProjectName("Dummy Project Name");

        assertFalse("Project name wasn't supposed to be valid.", jiraTracker.hasValidProjectName());
    }
}
