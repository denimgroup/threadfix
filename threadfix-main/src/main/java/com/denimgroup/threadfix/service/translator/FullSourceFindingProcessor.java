////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleanerFactory;
import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParserFactory;
import com.denimgroup.threadfix.service.SanitizedLogger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

class FullSourceFindingProcessor implements FindingProcessor {

    private static final SanitizedLogger log = new SanitizedLogger("FullSourceFindingProcessor");

    @Nullable
	private final EndpointDatabase database;

    @Nullable
	private final ParameterParser parameterParser;

    @NotNull
	private final FindingProcessor noSourceProcessor;
	
	public FullSourceFindingProcessor(ProjectConfig config, Scan scan) {
        PathCleaner cleaner = PathCleanerFactory.getPathCleaner(
				config.getFrameworkType(), scan.toPartialMappingList());
		
		noSourceProcessor = new NoSourceFindingProcessor(cleaner);
		
		database = EndpointDatabaseFactory.getDatabase(config.getRootFile(),
				config.getFrameworkType(), cleaner);
		
		parameterParser = ParameterParserFactory.getParameterParser(config);

		log.info("Initialized with EndpointDatabase = " + database);
		log.info("Initialized with PathCleaner = " + cleaner);
		log.info("Initialized with ParameterParser = " + parameterParser);
	}

	@Override
	public void process(@NotNull Finding finding) {
		String parameter = null;

        Endpoint endpoint = null;

        if (parameterParser != null) {
            if (finding.getSurfaceLocation() != null) {
                parameter = parameterParser.parse(finding.toEndpointQuery());
                finding.getSurfaceLocation().setParameter(parameter);
            }
        }

        if (database != null) {
            endpoint = database.findBestMatch(finding.toEndpointQuery());
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
			noSourceProcessor.process(finding);
		}
	}
}
