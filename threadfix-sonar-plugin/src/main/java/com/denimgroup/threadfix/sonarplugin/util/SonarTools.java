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
import org.sonar.api.component.ResourcePerspectives;
import org.sonar.api.issue.Issuable;
import org.sonar.api.issue.Issue;
import org.sonar.api.resources.Resource;
import org.sonar.api.rule.RuleKey;

import java.util.Collection;

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

    public static void addIssue(ResourcePerspectives resourcePerspectives, Resource resource, VulnerabilityMarker vulnerability) {
        if (resource != null) {

            LOG.debug("Got a resource properly.");

            Issuable issuable = resourcePerspectives.as(Issuable.class, resource);
            if(issuable != null) {

                String repositoryKey = ThreadFixCWERulesDefinition.getKey(resource.getLanguage().getKey());
                RuleKey key = RuleKey.of(repositoryKey, "cwe-" + vulnerability.getGenericVulnId());

                String lineNumber = vulnerability.getLineNumber();
                lineNumber = "-1".equals(lineNumber) || "0".equals(lineNumber) ? "1" : lineNumber;
                Issue issue = issuable
                        .newIssueBuilder()
                        .ruleKey(key)
                        .line(Integer.valueOf(lineNumber))
                        .severity(ThreadFixTools.getSonarSeverity(vulnerability))
                        .message(buildMessage(vulnerability)).build();

                if (issuable.addIssue(issue)) {
                    LOG.debug("Successfully added issue " + issue);
                } else {
                    LOG.debug("Failed to add issue " + issue);
                }
            }
        } else {
            LOG.debug("Got null resource for path " + vulnerability.getFilePath());
        }
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
