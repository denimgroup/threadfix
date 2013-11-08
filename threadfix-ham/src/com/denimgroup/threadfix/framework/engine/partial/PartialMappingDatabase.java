package com.denimgroup.threadfix.framework.engine.partial;

import java.util.List;

public interface PartialMappingDatabase {
	
	void addMappings(Iterable<PartialMapping> mappings);

	PartialMapping findBestMatch(PartialMapping mapping);
	
	List<PartialMapping> findAllMatches(PartialMapping mapping);
	
}
