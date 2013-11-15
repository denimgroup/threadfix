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
package com.denimgroup.threadfix.framework.impl.spring;

import java.util.List;

import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class SpringPathCleaner implements PathCleaner {
	
	public static final String GENERIC_INT_SEGMENT = "{id}";
	public static final String JSESSIONID = ";jsessionid=";
	@Nullable
    public static final SpringPathCleaner INSTANCE = new SpringPathCleaner(null);
	
	private final String dynamicRoot, staticRoot;
	
	// with scan
	public SpringPathCleaner(List<PartialMapping> partialMappings) {
		staticRoot  = CommonPathFinder.findOrParseProjectRoot(partialMappings);
		dynamicRoot = CommonPathFinder.findOrParseUrlPath(partialMappings);
	}
	
	// no scan
	public SpringPathCleaner(String dynamicRoot, String staticRoot) {
		this.staticRoot  = staticRoot;
		this.dynamicRoot = dynamicRoot;
	}
	
	@Override
	public String cleanStaticPath(@NotNull String filePath) {
		String relativeFilePath = filePath;
		
		if (staticRoot != null && filePath.startsWith(staticRoot)) {
			relativeFilePath = filePath.substring(staticRoot.length());
		}
		
		return relativeFilePath;
	}

	@Override
	public String cleanDynamicPath(@NotNull String urlPath) {
		
		String relativeUrlPath = urlPath;
		
		if (dynamicRoot != null &&
				urlPath.startsWith(dynamicRoot)) {
			relativeUrlPath = urlPath.substring(dynamicRoot.length());
		}
		
        String escaped = relativeUrlPath;

        if (escaped.contains(JSESSIONID)) {
            escaped = escaped.substring(0, escaped.indexOf(JSESSIONID));
        }

        escaped = escaped
                .replaceAll("/[0-9]+/", "/" + GENERIC_INT_SEGMENT + "/")
                .replaceAll("\\.html", "")
                .replaceAll("/[0-9]+$", "/" + GENERIC_INT_SEGMENT)
                .replaceAll("/\\*/", "/" + GENERIC_INT_SEGMENT + "/")
                .replaceAll("/$", "")
                .replaceAll("\\{[^\\}]+\\}", GENERIC_INT_SEGMENT);



        return escaped;
	}

    @Nullable
    @Override
    public String getDynamicPathFromStaticPath(@NotNull String filePath) {
        return filePath;
    }

    @Override
	public String getDynamicRoot() {
		return dynamicRoot;
	}

	@Override
	public String getStaticRoot() {
		return staticRoot;
	}
	
	@NotNull
    @Override
	public String toString() {
		return "Spring PathCleaner with dynamic root = " + dynamicRoot + ", static root = " + staticRoot;
	}

}
