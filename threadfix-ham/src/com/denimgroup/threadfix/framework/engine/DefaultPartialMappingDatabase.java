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
package com.denimgroup.threadfix.framework.engine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.denimgroup.threadfix.framework.beans.PartialMapping;


public class DefaultPartialMappingDatabase implements PartialMappingDatabase {
	
	private final Iterable<PartialMapping> partialMappings;
	
	private Map<String, List<PartialMapping>>
		dynamicMap = new HashMap<>(),
		staticMap  = new HashMap<>();
	
	public DefaultPartialMappingDatabase(Iterable<PartialMapping> partialMappings) {
		
		if (partialMappings == null) {
			this.partialMappings = new ArrayList<>();
		} else {
			this.partialMappings = partialMappings;
		}
		
		buildMaps();
	}
	
	private void buildMaps() {
		for (PartialMapping partialMapping : partialMappings) {
			if (partialMapping != null && partialMapping.getDynamicPath() != null) {
				if (!dynamicMap.containsKey(partialMapping.getDynamicPath())) {
					dynamicMap.put(partialMapping.getDynamicPath(), new ArrayList<PartialMapping>());
				}
				
				dynamicMap.get(partialMapping.getDynamicPath()).add(partialMapping);
			}
			
			if (partialMapping != null && partialMapping.getStaticPath() != null) {
				if (!staticMap.containsKey(partialMapping.getStaticPath())) {
					staticMap.put(partialMapping.getStaticPath(), new ArrayList<PartialMapping>());
				}
				
				staticMap.get(partialMapping.getStaticPath()).add(partialMapping);
			}
		}
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
		if (query.getDynamicPath() != null && dynamicMap.get(query.getDynamicPath()) != null) {
			List<PartialMapping> mappings = dynamicMap.get(query.getDynamicPath());
			
			if (!mappings.isEmpty()) {
				return mappings;
			}
		}
		
		if (query.getStaticPath() != null && staticMap.get(query.getStaticPath()) != null){
			List<PartialMapping> mappings = staticMap.get(query.getStaticPath());
			
			if (!mappings.isEmpty()) {
				return mappings;
			}
		}
		
		return new ArrayList<>();
	}
	
}
