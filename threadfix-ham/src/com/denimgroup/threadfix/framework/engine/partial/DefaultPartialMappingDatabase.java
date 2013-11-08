////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.engine.partial;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;

class DefaultPartialMappingDatabase implements PartialMappingDatabase {
	
	private final PathCleaner pathCleaner;
	
	private Map<String, List<PartialMapping>>
		dynamicMap = new HashMap<>(),
		staticMap  = new HashMap<>();
	
	public DefaultPartialMappingDatabase(Iterable<PartialMapping> partialMappings,
			PathCleaner pathCleaner) {
		
		this.pathCleaner = pathCleaner;
		
		if (partialMappings == null) {
			addToMap(new ArrayList<PartialMapping>());
		} else {
			addToMap(partialMappings);
		}
	}
	
	private void addToMap(Iterable<PartialMapping> partialMappings) {
		for (PartialMapping partialMapping : partialMappings) {
			if (isComplete(partialMapping)) {
				addToMap(dynamicMap, pathCleaner.cleanDynamicPath(partialMapping.getDynamicPath()), partialMapping);
				addToMap(staticMap, pathCleaner.cleanStaticPath(partialMapping.getStaticPath()), partialMapping);
			}
		}
	}
	
	private void addToMap(Map<String, List<PartialMapping>> map, String key, PartialMapping mapping) {
		if (key != null) {
			if (!map.containsKey(key)) {
				map.put(key, new ArrayList<PartialMapping>());
			}
			
			map.get(key).add(clean(mapping));
		}
	}
	
	private PartialMapping clean(PartialMapping input) {
		return new DefaultPartialMapping(
				pathCleaner.cleanStaticPath(input.getStaticPath()),
				pathCleaner.cleanDynamicPath(input.getDynamicPath())
				);
	}
	
	private boolean isComplete(PartialMapping mapping) {
		return mapping != null &&
				mapping.getDynamicPath() != null &&
				mapping.getStaticPath() != null;
	}

	@Override
	public PartialMapping findBestMatch(PartialMapping query) {
		PartialMapping returnMapping = null;
		
		List<PartialMapping> mappings = findAllMatches(query);
		
		if (!mappings.isEmpty()) {
			returnMapping = mappings.get(0);
		}
		
		return returnMapping;
	}

	@Override
	public List<PartialMapping> findAllMatches(PartialMapping query) {
		List<PartialMapping> maybeMappings = new ArrayList<PartialMapping>();
		if (query != null) {
			maybeMappings = getMappingsIfPresent(dynamicMap, pathCleaner.cleanDynamicPath(query.getDynamicPath()));
			
			if (maybeMappings.isEmpty()) {
				maybeMappings = getMappingsIfPresent(staticMap, pathCleaner.cleanDynamicPath(query.getDynamicPath()));
			}
		}
		
		return maybeMappings;
	}
	
	private List<PartialMapping> getMappingsIfPresent(Map<String, List<PartialMapping>> map, String key) {
		List<PartialMapping> mappings = new ArrayList<>();
		
		if (key != null && map.get(key) != null){
			mappings = map.get(key);
		}
		
		return mappings;
	}

	@Override
	public void addMappings(Iterable<PartialMapping> queries) {
		addToMap(queries);
	}
	
}
