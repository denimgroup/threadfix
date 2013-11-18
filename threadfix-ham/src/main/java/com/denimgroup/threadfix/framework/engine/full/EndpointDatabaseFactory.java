package com.denimgroup.threadfix.framework.engine.full;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.denimgroup.threadfix.framework.engine.FrameworkCalculator;
import com.denimgroup.threadfix.framework.engine.ProjectConfig;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleanerFactory;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.impl.jsp.JSPMappings;
import com.denimgroup.threadfix.framework.impl.spring.SpringControllerMappings;
import com.denimgroup.threadfix.framework.util.SanitizedLogger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class EndpointDatabaseFactory {
	
	private static final SanitizedLogger log = new SanitizedLogger("EndpointDatabaseFactory");

    @Nullable
    public static EndpointDatabase getDatabase(@NotNull ProjectConfig projectConfig) {

        EndpointDatabase database = null;

        if (projectConfig.getRootFile() != null) {
            if (projectConfig.getFrameworkType() != null &&
                    projectConfig.getFrameworkType() != FrameworkType.DETECT) {
                database = getDatabase(projectConfig.getRootFile(), projectConfig.getFrameworkType());
            } else {
                database = getDatabase(projectConfig.getRootFile());
            }
        }

        return database;
    }

	@Nullable
    public static EndpointDatabase getDatabase(@NotNull File rootFile) {
		FrameworkType type = FrameworkCalculator.getType(rootFile);
		return getDatabase(rootFile, type);
	}
	
	@Nullable
    public static EndpointDatabase getDatabase(@NotNull File rootFile, List<PartialMapping> partialMappings) {
		FrameworkType type = FrameworkCalculator.getType(rootFile);
		
		return getDatabase(rootFile, type, partialMappings);
	}

	@Nullable
    public static EndpointDatabase getDatabase(@NotNull File rootFile, @NotNull FrameworkType frameworkType) {
		return getDatabase(rootFile, frameworkType, new ArrayList<PartialMapping>());
	}
	
	@Nullable
    public static EndpointDatabase getDatabase(@NotNull File rootFile, @NotNull FrameworkType frameworkType, List<PartialMapping> partialMappings) {
		PathCleaner cleaner = PathCleanerFactory.getPathCleaner(frameworkType, partialMappings);
		
		return getDatabase(rootFile, frameworkType, cleaner);
	}
	
	@Nullable
    public static EndpointDatabase getDatabase(@NotNull File rootFile, @NotNull FrameworkType frameworkType, PathCleaner cleaner) {
		EndpointGenerator generator = null;
		
		switch (frameworkType) {
			case JSP:        generator = new JSPMappings(rootFile);              break;
			case SPRING_MVC: generator = new SpringControllerMappings(rootFile); break;
			default:
		}
		
		log.info("Returning database with generator: " + generator);

		if (generator == null) {
            return null;
        } else {
		    return new GeneratorBasedEndpointDatabase(generator, cleaner, frameworkType);
        }
	}
	
}
