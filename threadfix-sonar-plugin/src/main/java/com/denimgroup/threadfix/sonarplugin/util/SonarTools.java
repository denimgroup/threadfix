////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.sonarplugin.util;

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.sonarplugin.rules.ThreadFixCWERulesDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.SensorContext;
import org.sonar.api.batch.SonarIndex;
import org.sonar.api.issue.Issuable;
import org.sonar.api.issue.Issue;
import org.sonar.api.resources.Resource;
import org.sonar.api.rule.RuleKey;

import javax.annotation.Nonnull;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collection;

import static com.denimgroup.threadfix.CloseableUtils.closeQuietly;

/**
 * Created by mcollins on 2/4/15.
 */
public class SonarTools {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixTools.class);

    private SonarTools(){}

    public static Resource resourceOf(SonarIndex sonarIndex, SensorContext context, final String filePath) {

        Resource resource = searchAllResources(sonarIndex, filePath);

        if (context.getResource(resource) != null) {
            return resource;
        } else {
            LOG.debug("File \"{}\" is not indexed. Skip it.", filePath);
            return null;
        }
    }

    private static Resource searchAllResources(SonarIndex sonarIndex, final String componentKey) {
        if (componentKey == null || "".equals(componentKey)) {
            LOG.debug("Empty marker passed to searchAllResources.");
            return null;
        }

        final Collection<Resource> resources = sonarIndex.getResources();

        for (final Resource resource : resources) {
            if (resource.getKey().endsWith(componentKey) || componentKey.endsWith(resource.getKey())) {
                LOG.debug("Found resource for [" + componentKey + "]");
                LOG.debug("Resource class type: [" + resource.getClass().getName() + "]");
                LOG.debug("Resource key: [" + resource.getKey() + "]");
                LOG.debug("Resource id: [" + resource.getId() + "]");
                return resource;
            } else {
                LOG.debug("no match for " + resource.getKey());
            }
        }

        LOG.debug("No resource found for component [" + componentKey + "]");
        return null;
    }

    public static void addIssue(@Nonnull Issuable issuable, @Nonnull Resource resource, VulnerabilityMarker vulnerability) {

        String repositoryKey = ThreadFixCWERulesDefinition.getKey(resource.getLanguage().getKey());
        RuleKey key = RuleKey.of(repositoryKey, "cwe-" + vulnerability.getGenericVulnId());

        Integer line = getLineNumber(vulnerability);

        File file = getValidFile(resource);
        Integer lineCount = file == null ? 0 : getLineCount(file);

        if (lineCount != 0) {
            if (lineCount < line) {
                LOG.debug("Mismatched line numbers! Data says " + line + ", total line count is " + lineCount);
                line = lineCount - 1;
            }

            Issue issue = issuable
                    .newIssueBuilder()
                    .ruleKey(key)
                    .line(line)
                    .severity(ThreadFixTools.getSonarSeverity(vulnerability))
                    .message(buildMessage(vulnerability)).build();

            if (issuable.addIssue(issue)) {
                LOG.debug("Successfully added issue " + issue);
            } else {
                LOG.debug("Failed to add issue " + issue);
            }
        } else {
            LOG.debug("Got 0 lines for resource " + resource + ", not filing an issue.");
        }
    }

    private static Integer getLineNumber(VulnerabilityMarker vulnerability) {
        String lineNumber = vulnerability.getLineNumber();
        lineNumber = "-1".equals(lineNumber) || "0".equals(lineNumber) ? "1" : lineNumber;

        if (!lineNumber.matches("^[0-9]+$")) {
            lineNumber = "1";
        }

        return Integer.valueOf(lineNumber);
    }

    private static File getValidFile(Resource resource) {

        if (resource.getPath() != null) {
            File file = new File(resource.getPath());

            if (file.exists()) {
                LOG.info("Found file at " + file.getAbsolutePath());

                return file;
            } else {
                LOG.info("No file found for " + file.getPath());
            }
        } else {
            LOG.info("Path was null for " + resource);
        }

        return null;
    }

    private static Integer getLineCount(File file) {
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(new FileReader(file));

            int lines = 0;
            while (reader.readLine() != null) lines++;
            return lines;
        } catch (IOException e) {
            LOG.error("Got IOException trying to read from file " + file, e);
        } finally {
            closeQuietly(reader);
        }
        return 0;
    }

    private static String buildMessage(VulnerabilityMarker vulnerability) {
        StringBuilder returnString = new StringBuilder().append("Scanners: ").append(CollectionUtils.join(", ", vulnerability.getScanners()));

        String parameter = vulnerability.getParameter();
        if (parameter != null) {
            returnString.append("; Parameter: ").append(parameter);
        }

        return returnString.append("; Type: ").append(vulnerability.getGenericVulnName()).toString();
    }

}
