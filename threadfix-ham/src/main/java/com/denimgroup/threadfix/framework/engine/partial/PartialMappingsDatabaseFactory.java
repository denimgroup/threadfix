package com.denimgroup.threadfix.framework.engine.partial;

import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleanerFactory;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;

public class PartialMappingsDatabaseFactory {

	private PartialMappingsDatabaseFactory() {}
	
	@Nullable
    public static PartialMappingDatabase getPartialMappingsDatabase(@NotNull List<PartialMapping> seedMappings,
                                                                    @NotNull FrameworkType frameworkType) {
		PathCleaner cleaner = PathCleanerFactory.getPathCleaner(frameworkType, seedMappings);
		
		return new DefaultPartialMappingDatabase(seedMappings, cleaner);
	}
	
}
