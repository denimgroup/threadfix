package com.denimgroup.threadfix.framework.engine.partial;

import java.util.List;

import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleanerFactory;
import com.denimgroup.threadfix.framework.enums.FrameworkType;

public class PartialMappingsDatabaseFactory {

	private PartialMappingsDatabaseFactory() {}
	
	public static PartialMappingDatabase getPartialMappingsDatabase(List<PartialMapping> seedMappings, FrameworkType frameworkType) {
		PathCleaner cleaner = PathCleanerFactory.getPathCleaner(frameworkType, seedMappings);
		
		return new DefaultPartialMappingDatabase(seedMappings, cleaner);
	}
	
}
