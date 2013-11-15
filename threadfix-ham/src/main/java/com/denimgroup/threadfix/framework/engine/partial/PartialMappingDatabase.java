package com.denimgroup.threadfix.framework.engine.partial;

import java.util.List;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public interface PartialMappingDatabase {

	void addMappings(@NotNull Iterable<PartialMapping> mappings);

    @Nullable
	PartialMapping findBestMatch(PartialMapping mapping);

    @NotNull
	List<PartialMapping> findAllMatches(PartialMapping mapping);
	
}
