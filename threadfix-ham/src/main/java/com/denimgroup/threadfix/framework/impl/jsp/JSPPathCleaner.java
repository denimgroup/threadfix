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

package com.denimgroup.threadfix.framework.impl.jsp;

import com.denimgroup.threadfix.framework.engine.cleaner.DefaultPathCleaner;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;

public class JSPPathCleaner extends DefaultPathCleaner {

    public JSPPathCleaner(List<PartialMapping> partialMappings) {
        super(CommonPathFinder.findOrParseProjectRoot(partialMappings, ".jsp"),
                CommonPathFinder.findOrParseUrlPath(partialMappings, ".jsp"));
    }

    public JSPPathCleaner(String staticRoot, String dynamicRoot) {
        super(staticRoot, dynamicRoot);
    }

    @Nullable
    @Override
    public String getDynamicPathFromStaticPath(@Nonnull String filePath) {
        String cleanedPath = filePath;

        if (staticRoot != null) {
            if (cleanedPath.contains("\\")) {
                cleanedPath = cleanedPath.replace('\\', '/');
            }

            String localRoot = staticRoot;

            if (!cleanedPath.startsWith(localRoot) &&
                    cleanedPath.indexOf("/") != 0) {
                cleanedPath = "/" + cleanedPath;
            }

            if (!cleanedPath.startsWith(localRoot) &&
                    localRoot.indexOf("/") != 0) {
                localRoot = "/" + localRoot;
            }

            if (cleanedPath.startsWith(localRoot)) {
                cleanedPath = cleanedPath.substring(localRoot.length());
            }
        }

        return cleanedPath;
    }

    @Override
    public String cleanDynamicPath(@Nonnull String urlPath) {
        String cleanedPath = urlPath;

        if (cleanedPath.contains("\\")) {
            cleanedPath = cleanedPath.replace('\\', '/');
        }

        if (dynamicRoot != null && cleanedPath.startsWith(dynamicRoot)) {
            cleanedPath = cleanedPath.substring(dynamicRoot.length());
        }

        if (cleanedPath.indexOf("/") != 0) {
            cleanedPath = "/" + cleanedPath;
        }

        return cleanedPath;
    }

    @Nonnull
    @Override
    public String toString() {
        return "[JSP PathCleaner dynamicRoot = " +
                dynamicRoot + ", staticRoot = " + staticRoot + "]";
    }

}
