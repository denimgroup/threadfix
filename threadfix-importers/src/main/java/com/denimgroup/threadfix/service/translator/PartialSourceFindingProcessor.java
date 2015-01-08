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
package com.denimgroup.threadfix.service.translator;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.ThreadFixInterface;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleanerFactory;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParserFactory;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.engine.partial.PartialMappingDatabase;
import com.denimgroup.threadfix.framework.engine.partial.PartialMappingsDatabaseFactory;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

class PartialSourceFindingProcessor implements FindingProcessor {

    protected static final SanitizedLogger LOG = new SanitizedLogger(PartialSourceFindingProcessor.class);

    @Nullable
    private final PartialMappingDatabase database;

    @Nullable
    private final ParameterParser parameterParser;

    @Nonnull
    private final FindingProcessor noSourceProcessor;

    public PartialSourceFindingProcessor(@Nonnull ProjectConfig projectConfig,
                                         @Nonnull Scan scan) {
        PathCleaner cleaner = PathCleanerFactory.getPathCleaner(
                projectConfig.getFrameworkType(), ThreadFixInterface.toPartialMappingList(scan));

        noSourceProcessor = new NoSourceFindingProcessor(cleaner);

        database = PartialMappingsDatabaseFactory.getPartialMappingsDatabase(
                ThreadFixInterface.toPartialMappingList(scan), projectConfig.getFrameworkType());

        parameterParser = ParameterParserFactory.getParameterParser(projectConfig);

        LOG.info("Initialized with EndpointDatabase = " + database);
        LOG.info("Initialized with PathCleaner = " + cleaner);
        LOG.info("Initialized with ParameterParser = " + parameterParser);
    }

    public void train(@Nonnull Application application) {
        if (database != null && application.getScans() != null) {
            for (Scan scan : application.getScans()) {
                if (scan != null) {
                    database.addMappings(ThreadFixInterface.toPartialMappingList(scan));
                }
            }
        }
    }

    @Override
    public void process(@Nonnull Finding finding) {
        PartialMapping query = ThreadFixInterface.toPartialMapping(finding);

        PartialMapping endpoint = null;

        if (database != null) {
            endpoint = database.findBestMatch(query);
        }

        if (parameterParser != null && finding.getSurfaceLocation() != null) {
            String parameter = parameterParser.parse(ThreadFixInterface.toEndpointQuery(finding));
            finding.getSurfaceLocation().setParameter(parameter);
        }

        if (endpoint != null) {
            finding.setCalculatedFilePath(endpoint.getStaticPath());
            finding.setCalculatedUrlPath(endpoint.getDynamicPath());
        } else {
            noSourceProcessor.process(finding);
        }
    }

    @Override
    public void printStatistics() {

    }

}
