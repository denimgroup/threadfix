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
        vulnType = array[0];
        severity = array[1];
        path = array[2];
        parameter = array[3].equals("") ? null : array[3];
    }

    // This class assumes that every finding will have severity and vulnerability mappings.
    // This is probably a good thing.
    public boolean matches(Finding finding) {
        if (finding == null) {
            throw new IllegalArgumentException("Got a null finding. Fix the code.");
        } else if (finding.getSurfaceLocation() == null) {
            throw new IllegalArgumentException("Got a finding without a surface location.");
        }

        if (finding.getChannelVulnerability() == null) {
            throw new IllegalArgumentException("finding.getChannelVulnerability() is Null");
        }

        try{
        return matchesParameter(finding) &&
                finding.getSurfaceLocation().getPath().equals(path) &&
                finding.getChannelSeverity().getSeverityMap().getGenericSeverity().getName().equals(severity) &&
                finding.getChannelVulnerability().getGenericVulnerability().getName().equals(vulnType);
        } catch (NullPointerException e) {
            System.out.println("Null pointer caught");
        }
        return false;
    }

    private boolean matchesParameter(Finding finding) {
        return (finding.getSurfaceLocation().getParameter() == null && parameter == null) ||
                    (finding.getSurfaceLocation().getParameter() != null &&
                finding.getSurfaceLocation().getParameter().equals(parameter));
    }

    @Override
    public String toString() {
        return "SimpleFinding{" +
                "vulnType='" + vulnType + '\'' +
                ", severity='" + severity + '\'' +
                ", path='" + path + '\'' +
                ", parameter='" + parameter + '\'' +
                '}';
    }
}
