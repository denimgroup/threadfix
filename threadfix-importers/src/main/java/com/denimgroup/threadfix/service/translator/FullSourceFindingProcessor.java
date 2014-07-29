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
package com.denimgroup.threadfix.service.translator;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.ThreadFixInterface;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleanerFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParserFactory;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

class FullSourceFindingProcessor implements FindingProcessor {

    private static final SanitizedLogger LOG = new SanitizedLogger(FullSourceFindingProcessor.class);

    @Nullable
    private final EndpointDatabase database;

    @Nullable
    private final ParameterParser parameterParser;

    @Nonnull
    private final FindingProcessor noSourceProcessor;

    private int numberMissed = 0, total = 0, foundParameter;
    private long startTime = 0L;

    public FullSourceFindingProcessor(ProjectConfig config, Scan scan) {
        PathCleaner cleaner = PathCleanerFactory.getPathCleaner(
                config.getFrameworkType(), ThreadFixInterface.toPartialMappingList(scan));

        noSourceProcessor = new NoSourceFindingProcessor(cleaner);

        database = EndpointDatabaseFactory.getDatabase(config.getRootFile(),
                config.getFrameworkType(), cleaner);

        parameterParser = ParameterParserFactory.getParameterParser(config);

        startTime = System.currentTimeMillis();

        LOG.info("Initialized with EndpointDatabase = " + database);
        LOG.info("Initialized with PathCleaner = " + cleaner);
        LOG.info("Initialized with ParameterParser = " + parameterParser);
    }

    @Override
    public void process(@Nonnull Finding finding) {
        String parameter = null;
        Endpoint endpoint = null;
        total++;

        if (parameterParser != null) {
            if (finding.getSurfaceLocation() != null) {
                parameter = parameterParser.parse(ThreadFixInterface.toEndpointQuery(finding));
                foundParameter++;
                finding.getSurfaceLocation().setParameter(parameter);
            }
        }

        if (database != null) {
            endpoint = database.findBestMatch(ThreadFixInterface.toEndpointQuery(finding));
        }

        if (endpoint != null) {
            finding.setCalculatedFilePath(endpoint.getFilePath());
            finding.setCalculatedUrlPath(endpoint.getUrlPath());

            if (parameter != null) {
                finding.setEntryPointLineNumber(endpoint.getLineNumberForParameter(parameter));
            } else {
                finding.setEntryPointLineNumber(endpoint.getStartingLineNumber());
            }

        } else {

            numberMissed++;

            // let's try without the parameter in order to degrade gracefully
            noSourceProcessor.process(finding);
        }
    }

    @Override
    public void printStatistics() {
        LOG.info("Printing statistics for FullSourceFindingProcessor.");

        LOG.info("Successfully found endpoints for " + (total - numberMissed) +
                " out of " + total + " findings " +
                "(" + (100.0 * (total - numberMissed) / total) + "%).");
        LOG.info("Successfully found parameters for " + foundParameter +
                " out of " + total + " findings " +
                "(" + (100.0 * foundParameter / total) + "%)");
        LOG.info("Processing took " + (System.currentTimeMillis() - startTime) + " ms.");

        noSourceProcessor.printStatistics();
    }
}
