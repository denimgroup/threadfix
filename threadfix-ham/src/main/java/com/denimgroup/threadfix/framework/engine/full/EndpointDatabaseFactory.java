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

package com.denimgroup.threadfix.framework.engine.full;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleanerFactory;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.impl.dotNet.DotNetMappings;
import com.denimgroup.threadfix.framework.impl.dotNetWebForm.WebFormsEndpointGenerator;
import com.denimgroup.threadfix.framework.impl.jsp.JSPMappings;
import com.denimgroup.threadfix.framework.impl.spring.SpringControllerMappings;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class EndpointDatabaseFactory {
	
	private static final SanitizedLogger log = new SanitizedLogger("EndpointDatabaseFactory");

    @Nullable
    public static EndpointDatabase getDatabase(@Nonnull ProjectConfig projectConfig) {

        EndpointDatabase database = null;

        File rootFile = projectConfig.getRootFile();

        if (rootFile != null) {
            if (projectConfig.getFrameworkType() != FrameworkType.DETECT) {
                database = getDatabase(rootFile, projectConfig.getFrameworkType());
            } else {
                database = getDatabase(rootFile);
            }
        }

        return database;
    }

	@Nullable
    public static EndpointDatabase getDatabase(@Nonnull String rootFile) {
        File file = new File(rootFile);

        assert file.exists() : rootFile + " didn't exist.";
        assert file.isDirectory() : rootFile + " wasn't a directory.";

        return getDatabase(file);
	}

	@Nullable
    public static EndpointDatabase getDatabase(@Nonnull File rootFile) {
		FrameworkType type = FrameworkCalculator.getType(rootFile);
		return getDatabase(rootFile, type);
	}
	
	@Nullable
    public static EndpointDatabase getDatabase(@Nonnull File rootFile, List<PartialMapping> partialMappings) {
		FrameworkType type = FrameworkCalculator.getType(rootFile);
		
		return getDatabase(rootFile, type, partialMappings);
	}

	@Nullable
    public static EndpointDatabase getDatabase(@Nonnull File rootFile, @Nonnull FrameworkType frameworkType) {
		return getDatabase(rootFile, frameworkType, new ArrayList<PartialMapping>());
	}
	
	@Nullable
    public static EndpointDatabase getDatabase(@Nonnull File rootFile, @Nonnull FrameworkType frameworkType, List<PartialMapping> partialMappings) {
		PathCleaner cleaner = PathCleanerFactory.getPathCleaner(frameworkType, partialMappings);
		
		return getDatabase(rootFile, frameworkType, cleaner);
	}
	
	@Nullable
    public static EndpointDatabase getDatabase(@Nonnull File rootFile, @Nonnull FrameworkType frameworkType, PathCleaner cleaner) {

        log.info("Creating database with root file = " +
                rootFile.getAbsolutePath() +
                " and framework type = " +
                frameworkType +
                " and path cleaner = " +
                cleaner);


		EndpointGenerator generator = null;
		
		switch (frameworkType) {
            case NONE:
            case DETECT:      break;
            case JSP:         generator = new JSPMappings(rootFile);              break;
			case SPRING_MVC:  generator = new SpringControllerMappings(rootFile); break;
			case DOT_NET_MVC: generator = new DotNetMappings(rootFile);           break;
            case DOT_NET_WEB_FORMS: generator = new WebFormsEndpointGenerator(rootFile); break;

			default:
                String logError = "You should never be here. You are missing a case statement for " + frameworkType;
                log.error(logError);
                assert false : logError;
		}
		
		log.info("Returning database with generator: " + generator);

        if (cleaner != null) {
            cleaner.setEndpointGenerator(generator);
        }

		if (generator == null) {
            return null;
        } else {
		    return new GeneratorBasedEndpointDatabase(generator, cleaner, frameworkType);
        }
	}

	@Nullable
    public static EndpointDatabase getDatabase(@Nonnull EndpointGenerator generator,
                                               @Nonnull FrameworkType frameworkType, PathCleaner cleaner) {
        return new GeneratorBasedEndpointDatabase(generator, cleaner, frameworkType);
	}
	
}
