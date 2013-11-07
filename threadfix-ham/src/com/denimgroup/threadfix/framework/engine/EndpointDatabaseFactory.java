package com.denimgroup.threadfix.framework.engine;

import java.io.File;

import com.denimgroup.threadfix.framework.beans.PathCleaner;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.impl.jsp.JSPMappings;
import com.denimgroup.threadfix.framework.impl.spring.SpringControllerMappings;
import com.denimgroup.threadfix.framework.util.SanitizedLogger;

public class EndpointDatabaseFactory {
	
	private static final SanitizedLogger log = new SanitizedLogger("MergeConfigurationGenerator");
	
	public static EndpointDatabase getDatabaseNoCleaner(File rootFile) {
		return getDatabase(rootFile, new DefaultPathCleaner("", ""));
	}

	public static EndpointDatabase getDatabase(File rootFile, PathCleaner cleaner) {
		log.info("Attempting to calculate framework type based on project contents.");
		
		FrameworkType type = FrameworkCalculator.getType(rootFile);
		
		log.info("Calculated framework : " + type + ".");
		
		return getDatabase(rootFile, type, cleaner);
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
