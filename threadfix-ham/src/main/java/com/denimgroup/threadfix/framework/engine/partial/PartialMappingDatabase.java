package com.denimgroup.threadfix.framework.engine.partial;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;

public interface PartialMappingDatabase {

	void addMappings(Iterable<PartialMapping> mappings);

    @Nullable
	PartialMapping findBestMatch(PartialMapping mapping);

    @NotNull
	List<PartialMapping> findAllMatches(PartialMapping mapping);
	
}
