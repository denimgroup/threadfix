package com.denimgroup.threadfix.importer.utils;

import com.denimgroup.threadfix.data.entities.Finding;

import static junit.framework.Assert.assertTrue;

/**
 * Created by mac on 2/6/14.
 */
public class SimpleFinding {

    private final String vulnType, severity, path, parameter;

    public SimpleFinding(String[] array) {
        assertTrue(array.length == 4);
        this.vulnType = array[0];
        this.severity = array[1];
        this.path = array[2];
        this.parameter = array[3];
    }

    public boolean matches(Finding finding) {
        return finding.getSurfaceLocation().getParameter().equals(parameter) &&
                finding.getSurfaceLocation().getPath().equals(path) &&
                finding.getChannelSeverity().getSeverityMap().getGenericSeverity().getName().equals(severity) &&
                finding.getChannelVulnerability().getGenericVulnerability().getName().equals(vulnType);
    }

}
