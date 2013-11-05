package com.denimgroup.threadfix.framework.engine;

import java.util.List;

import com.denimgroup.threadfix.framework.beans.PartialMapping;

public interface PartialMappingDatabase {

	PartialMapping findBestMatch(PartialMapping query);
	
	List<PartialMapping> findAllMatches(PartialMapping query);
	
}
