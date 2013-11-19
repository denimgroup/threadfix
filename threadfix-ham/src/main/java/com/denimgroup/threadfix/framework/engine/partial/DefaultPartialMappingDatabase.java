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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

class DefaultPartialMappingDatabase implements PartialMappingDatabase {

    @NotNull
	private final PathCleaner pathCleaner;
	
	@NotNull
    private Map<String, List<PartialMapping>>
		dynamicMap = new HashMap<>(),
		staticMap  = new HashMap<>();
	
	public DefaultPartialMappingDatabase(@Nullable Iterable<PartialMapping> partialMappings,
                                         @NotNull PathCleaner pathCleaner) {
		
		this.pathCleaner = pathCleaner;
		
		if (partialMappings == null) {
			addToMap(new ArrayList<PartialMapping>());
		} else {
			addToMap(partialMappings);
		}


	}

	private void addToMap(@NotNull Iterable<PartialMapping> partialMappings) {
		for (PartialMapping partialMapping : partialMappings) {
			if (isComplete(partialMapping)) {
				addToMap(dynamicMap, cleanDynamicPath(partialMapping.getDynamicPath()), partialMapping);
				addToMap(staticMap, cleanStaticPath(partialMapping.getStaticPath()), partialMapping);
			}
		}
	}
	
	private void addToMap(@NotNull Map<String, List<PartialMapping>> map,
                          @Nullable String key, @NotNull PartialMapping mapping) {
		if (key != null) {
			if (!map.containsKey(key)) {
				map.put(key, new ArrayList<PartialMapping>());
			}
			
			map.get(key).add(clean(mapping));
		}
	}
	
	@Nullable
    private PartialMapping clean(@NotNull PartialMapping input) {

		return new DefaultPartialMapping(
				cleanStaticPath(input.getStaticPath()),
				cleanDynamicPath(input.getDynamicPath())
				);
	}
	
	private boolean isComplete(@Nullable PartialMapping mapping) {
		return mapping != null &&
				mapping.getDynamicPath() != null &&
				mapping.getStaticPath() != null &&
                !mapping.getDynamicPath().equals(mapping.getStaticPath());
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
    @NotNull
	public List<PartialMapping> findAllMatches(@Nullable PartialMapping query) {
		List<PartialMapping> maybeMappings = new ArrayList<>();
		if (query != null) {
			maybeMappings = getMappingsIfPresent(dynamicMap, cleanDynamicPath(query.getDynamicPath()));
			
			if (maybeMappings.isEmpty()) {
				maybeMappings = getMappingsIfPresent(staticMap, cleanStaticPath(query.getStaticPath()));
			}
		}
		
		return maybeMappings;
	}

    @Nullable
    private String cleanStaticPath(@Nullable String input) {
        if (input != null) {
            return pathCleaner.cleanStaticPath(input);
        } else {
            return null;
        }
    }

    @Nullable
    private String cleanDynamicPath(@Nullable String input) {
        if (input != null) {
            return pathCleaner.cleanDynamicPath(input);
        } else {
            return null;
        }
    }

    @NotNull
	private List<PartialMapping> getMappingsIfPresent(@NotNull Map<String, List<PartialMapping>> map, @Nullable String key) {
		List<PartialMapping> mappings = new ArrayList<>();
		
		if (key != null && map.get(key) != null){
			mappings = map.get(key);
		}
		
		return mappings;
	}

	@Override
	public void addMappings(@NotNull Iterable<PartialMapping> queries) {
		addToMap(queries);
	}
	
}
