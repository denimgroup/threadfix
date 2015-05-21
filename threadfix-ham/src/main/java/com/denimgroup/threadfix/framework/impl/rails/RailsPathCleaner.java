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
package com.denimgroup.threadfix.framework.impl.rails;

import com.denimgroup.threadfix.framework.engine.cleaner.DefaultPathCleaner;
import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.SocketPermission;
import java.util.List;

public class RailsPathCleaner extends DefaultPathCleaner {

    private static final String GENERIC_INT_SEGMENT = "{id}";
    private static final String VIEWS_PATH = "/views/";
    private static final String APP_PATH = "/app/";


    public RailsPathCleaner(List<PartialMapping> partialMappings) {
        super(partialMappings);
    }

    @Override
    public String cleanStaticPath(@Nonnull String filePath) {
        String cleanedPath = super.cleanStaticPath(filePath);
        if (cleanedPath.contains(VIEWS_PATH)) {
            cleanedPath = cleanedPath
                    .substring(cleanedPath.lastIndexOf(VIEWS_PATH) + VIEWS_PATH.length() - 1);
        }
        if (cleanedPath.contains(APP_PATH)) {
            cleanedPath = cleanedPath.substring(cleanedPath.indexOf(APP_PATH));
        }
        return cleanedPath;
    }

    @Override
    public String cleanDynamicPath(@Nonnull String urlPath) {
        String cleanedPath = super.cleanDynamicPath(urlPath);
        cleanedPath = cleanedPath.replaceAll("/[0-9]+/", "/" + GENERIC_INT_SEGMENT + "/")
                                 .replaceAll("/[0-9]+$", "/" + GENERIC_INT_SEGMENT);
        return cleanedPath;
    }

}
