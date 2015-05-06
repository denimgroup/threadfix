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

import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.RepositoryService;
import com.denimgroup.threadfix.service.repository.RepositoryServiceFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;

@Component
class FindingProcessorFactory extends SpringBeanAutowiringSupport {

    private static final SanitizedLogger LOG = new SanitizedLogger(FindingProcessorFactory.class);

    @Autowired private RepositoryServiceFactory repositoryServiceFactory;

    @Nonnull
    public static FindingProcessor getProcessor(@Nonnull Application application,
                                                @Nonnull Scan scan) {

        LOG.info("Determining proper FindingProcesser implementation for application " + application.getName() + " and new scan.");

        SourceCodeAccessLevel accessLevel = getSourceCodeAccessLevel(application, scan);
        File rootFile = getRootFile(application);
        FrameworkType frameworkType = getFrameworkType(application, accessLevel, rootFile, scan);

        ProjectConfig config = new ProjectConfig(frameworkType, accessLevel, rootFile, "/");

        FindingProcessor processor;

        if (accessLevel == SourceCodeAccessLevel.FULL) {
            LOG.info("Got full source code access from configured code location. Returning FullSourceFindingProcessor.");
            processor = new FullSourceFindingProcessor(config, scan);
        } else if (accessLevel == SourceCodeAccessLevel.PARTIAL) {
            LOG.info("Got partial source code access through static scans. Returning PartialSourceFindingProcessor.");
            PartialSourceFindingProcessor partialProcessor = new PartialSourceFindingProcessor(config, scan);
            partialProcessor.train(application);
            processor = partialProcessor;
        } else {
            LOG.info("Got no source code access. Returning NoSourceFindingProcessor.");
            processor = new NoSourceFindingProcessor(frameworkType, scan);
        }

        return processor;
    }

    @Nonnull
    private static SourceCodeAccessLevel getSourceCodeAccessLevel(
            @Nonnull Application application,
            @Nonnull Scan scan) {

        SourceCodeAccessLevel accessLevel = SourceCodeAccessLevel.NONE;

        if (application.getSourceCodeAccessLevelEnum() != SourceCodeAccessLevel.DETECT) {
            accessLevel = application.getSourceCodeAccessLevelEnum();
        } else if (!nullOrEmpty(application.getRepositoryUrl()) ||
                !nullOrEmpty(application.getRepositoryFolder())) {
            accessLevel = SourceCodeAccessLevel.FULL;
        } else if (scan.isStatic() || hasStaticScan(application)) {
            accessLevel = SourceCodeAccessLevel.PARTIAL;
        }

        return accessLevel;
    }

    private static boolean nullOrEmpty(String input) {
        return input == null || input.trim().isEmpty();
    }

    private static boolean hasStaticScan(Application application) {
		boolean hasStatic = false;
		
		for (Scan scan : application.getScans()) {
			if (scan != null && scan.isStatic()) {
				hasStatic = true;
				break;
			}
		}
		
		return hasStatic;
	}
	
	private static final String baseDirectory = "scratch/";
	
	@Nullable
	private static File getRootFile(Application application) {

        FindingProcessorFactory factory = new FindingProcessorFactory();

        RepositoryService repositoryService = factory.repositoryServiceFactory.getRepositoryService(application);

        if (repositoryService == null) {
            LOG.info("RepositoryService was null. " +
                     "Either we're not in a Spring context or no implementation was in the container.");
        } else {
            LOG.info("Successfully found RepositoryService.");
        }

		File applicationDirectory = DiskUtils.getScratchFile(baseDirectory + application.getId());

		if (repositoryService != null &&
                application.getRepositoryUrl() != null &&
                !application.getRepositoryUrl().trim().isEmpty()) {
			File file = repositoryService.cloneRepoToDirectory(application, applicationDirectory);

			if (file != null && file.exists()) {
				return file;
			} else {
				LOG.error("Unable to get repository from GIT");
				return applicationDirectory;
			}
		} else if (application.getRepositoryFolder() != null && !application.getRepositoryFolder().trim().isEmpty()) {
			File file = new File(application.getRepositoryFolder().trim());
			if (!file.exists() || !file.isDirectory()) {
				return applicationDirectory;
			} else {
				return file;
			}
		}

		return applicationDirectory;
	}

	@Nonnull
	private static FrameworkType getFrameworkType(Application application,
			SourceCodeAccessLevel accessLevel, File rootFile, Scan scan) {
		
		FrameworkType frameworkType = application.getFrameworkTypeEnum();

        LOG.info("Initial frameworkType was " + frameworkType);

		if (frameworkType == FrameworkType.DETECT) {
			if (accessLevel == SourceCodeAccessLevel.FULL) {
				if (rootFile != null) {
					frameworkType = FrameworkCalculator.getType(rootFile);
				} else {
					frameworkType = FrameworkType.NONE;
				}
			} else if (accessLevel == SourceCodeAccessLevel.PARTIAL){
				frameworkType = guessFrameworkTypeFromDataFlows(application, scan);
			} else if (accessLevel == SourceCodeAccessLevel.NONE){
				// TODO we can still figure out JSP / ASP / PHP
				frameworkType = FrameworkType.NONE;
			}
		}

        LOG.info("Final frameworkType was " + frameworkType);
		return frameworkType;
	}
	
	// TODO cache this information so we don't have to calculate every time
	private static FrameworkType guessFrameworkTypeFromDataFlows(Application application, Scan scan) {
		FrameworkType returnType = guessFrameworkType(scan);
		
		if (returnType == FrameworkType.NONE && application != null && application.getScans() != null) {
			for (Scan applicationScan : application.getScans()) {
				FrameworkType scanType = guessFrameworkType(applicationScan);
				if (scanType != FrameworkType.NONE) {
					returnType = scanType;
					break;
				}
			}
		}
		
		return returnType;
	}
	
	// TODO improve this
	private static FrameworkType guessFrameworkType(Scan scan) {

        LOG.info("Guessing framework type.");

		FrameworkType type = FrameworkType.NONE;
		
		if (scan != null && scan.isStatic() && scan.getFindings() != null &&
				!scan.getFindings().isEmpty()) {
			for (Finding finding : scan.getFindings()) {
				if (finding != null && finding.getStaticPathInformation() != null &&
						finding.getStaticPathInformation().guessFrameworkType() == FrameworkType.SPRING_MVC) {
					type = FrameworkType.SPRING_MVC;
					break;
				} else if (finding != null && finding.getSourceFileLocation() != null &&
						finding.getSourceFileLocation().endsWith(".jsp")) {
					type = FrameworkType.JSP;
					// There is intentionally not a break here. Since Spring projects also contain
					// JSP files sometimes, we only want to use JSP if no Spring hints are found.
				}
			}
		}

        LOG.info("Guessing framework type returned " + type + ".");

        return type;
	}
	
}
