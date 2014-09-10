////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.framework.engine.cleaner;

import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;

public class DefaultPathCleaner implements PathCleaner {

	protected final String staticRoot, dynamicRoot;
	
	public DefaultPathCleaner(String staticRoot, String dynamicRoot) {
		this.staticRoot  = staticRoot;

        // let's make sure that the last segment doesn't contain a .
        if (dynamicRoot != null) {
            String[] split = dynamicRoot.split("/");
            if (split[split.length - 1].contains(".")) {
                StringBuilder builder = new StringBuilder();

                // add all the segments except for the last one
                for (int i = 0; i < split.length - 1; i++) {
                    if (!"".equals(split[i])) {
                        builder.append('/').append(split[i]);
                    }
                }

                this.dynamicRoot = builder.toString();
            } else {
                this.dynamicRoot = dynamicRoot;
            }
        } else {
            this.dynamicRoot = null;
        }
	}
	
	public DefaultPathCleaner(List<PartialMapping> partialMappings){
		this(CommonPathFinder.findOrParseProjectRoot(partialMappings),
				CommonPathFinder.findOrParseUrlPath(partialMappings));
	}

	@Override
	public String cleanStaticPath(@Nonnull String filePath) {
		String cleanedPath = filePath;
		
		if (staticRoot != null && cleanedPath.startsWith(staticRoot)) {
			cleanedPath = cleanedPath.substring(staticRoot.length());
		}
		
		if (cleanedPath.contains("\\")) {
			cleanedPath = cleanedPath.replace('\\','/');
		}

        if (cleanedPath.indexOf("/") != 0) {
			cleanedPath = "/" + cleanedPath;
		}
		
		return cleanedPath;
	}

	@Override
	public String cleanDynamicPath(@Nonnull String urlPath) {
		String cleanedPath = urlPath;
		
		if (dynamicRoot != null && cleanedPath.startsWith(dynamicRoot)) {
			cleanedPath = cleanedPath.substring(dynamicRoot.length());
		}
		
		if (cleanedPath.contains("\\")) {
            cleanedPath = cleanedPath.replace('\\', '/');
		}
		
		if (cleanedPath.indexOf("/") != 0) {
			cleanedPath = "/" + cleanedPath;
		}
		
		return cleanedPath;
	}

    @Nullable
    @Override
    public String getDynamicPathFromStaticPath(@Nonnull String filePath) {
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
	
	@Nonnull
    @Override
	public String toString() {
		return "[PathCleaner dynamicRoot=" + dynamicRoot + ", staticRoot=" + staticRoot + "]";
	}

}
