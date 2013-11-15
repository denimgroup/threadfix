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

import java.io.File;

import org.eclipse.jgit.lib.Repository;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.framework.engine.FrameworkCalculator;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.service.repository.GitService;

class FindingProcessorFactory {

	@NotNull
	public static FindingProcessor getProcessor(@NotNull Application application,
			@NotNull Scan scan) {
		
		SourceCodeAccessLevel accessLevel = getSourceCodeAccessLevel(application, scan);
		File rootFile = getRootFile(application);
		FrameworkType frameworkType = getFrameworkType(application, accessLevel, rootFile, scan);
		
		ProjectConfig config = new ProjectConfig(frameworkType, accessLevel, rootFile, "/");
		
		FindingProcessor processor;
		
		if (accessLevel == SourceCodeAccessLevel.FULL) {
			processor = new FullSourceFindingProcessor(config, scan);
		} else if (accessLevel == SourceCodeAccessLevel.PARTIAL) {
			PartialSourceFindingProcessor partialProcessor = new PartialSourceFindingProcessor(config, scan);
			partialProcessor.train(application);
			processor = partialProcessor;
		} else {
			processor = new NoSourceFindingProcessor(frameworkType, scan);
		}
		
		return processor;
	}
	
	@NotNull
	private static SourceCodeAccessLevel getSourceCodeAccessLevel(
			@NotNull Application application,
			@NotNull Scan scan) {
		
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
		
		File applicationDirectory = new File(baseDirectory + application.getId());

		if (application.getRepositoryUrl() != null && !application.getRepositoryUrl().trim().isEmpty()) {
			Repository repo = GitService.cloneGitTreeToDirectory(application.getRepositoryUrl(), applicationDirectory);

			if (repo != null && repo.getWorkTree() != null && repo.getWorkTree().exists()) {
				return repo.getWorkTree();
			} else {
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

	@NotNull
	private static FrameworkType getFrameworkType(Application application,
			SourceCodeAccessLevel accessLevel, File rootFile, Scan scan) {
		
		FrameworkType frameworkType = application.getFrameworkTypeEnum();
		
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
		
		return type;
	}
	
}
