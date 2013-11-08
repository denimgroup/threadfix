package com.denimgroup.threadfix.framework.engine.full;

import java.io.File;
import java.util.ArrayList;

import com.denimgroup.threadfix.framework.engine.FrameworkCalculator;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleanerFactory;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.impl.jsp.JSPMappings;
import com.denimgroup.threadfix.framework.impl.spring.SpringControllerMappings;
import com.denimgroup.threadfix.framework.util.SanitizedLogger;

public class EndpointDatabaseFactory {
	
	private static final SanitizedLogger log = new SanitizedLogger("MergeConfigurationGenerator");
	
	public static EndpointDatabase getDatabase(File rootFile) {
		log.info("Attempting to calculate framework type based on project contents.");
		
		FrameworkType type = FrameworkCalculator.getType(rootFile);
		
		log.info("Calculated framework : " + type + ".");
		
		return getDatabase(rootFile, type);
	}

	public static EndpointDatabase getDatabase(File rootFile, FrameworkType frameworkType) {
		log.info("Attempting to retrieve path cleaner based on project contents.");
		
		PathCleaner cleaner = PathCleanerFactory.getPathCleaner(frameworkType, new ArrayList<PartialMapping>());
		
		log.info("Got PathCleaner : " + cleaner + ".");
		
		return getDatabase(rootFile, frameworkType, cleaner);
	}
	
	public static EndpointDatabase getDatabase(File rootFile, FrameworkType frameworkType, PathCleaner cleaner) {
		EndpointGenerator generator = null;
		
		switch (frameworkType) {
			case JSP:        generator = new JSPMappings(rootFile);              break;
			case SPRING_MVC: generator = new SpringControllerMappings(rootFile); break;
			default:
		}
		
		return new GeneratorBasedEndpointDatabase(generator, cleaner, frameworkType);
	}
	
}
