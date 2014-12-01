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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.cleaner.DefaultPathCleaner;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mac on 11/11/14.
 */
public class WebFormsPathCleaner extends DefaultPathCleaner {

    private static final SanitizedLogger LOG = new SanitizedLogger(WebFormsPathCleaner.class);

    public WebFormsPathCleaner(String staticRoot, String dynamicRoot) {
        super(staticRoot, dynamicRoot);
    }

    public WebFormsPathCleaner(List<PartialMapping> mappings) {
        super(mappings);
    }

    @Nullable
    @Override
    public String cleanStaticPath(@Nonnull String filePath) {
        String match = getLongestMatchingString(filePath, staticPaths);

        return match == null ? super.cleanStaticPath(filePath) : match;
    }

    @Nullable
    @Override
    public String cleanDynamicPath(@Nonnull String urlPath) {
        String match = getLongestMatchingString(urlPath, dynamicPaths);

        return match == null ? super.cleanDynamicPath(urlPath) : match;
    }

    // calculates match based on String.endsWith()
    private String getLongestMatchingString(String input, Set<String> possibilities) {
        int score = -1;
        String path = null;

        for (String staticPath : possibilities) {
            if (input.endsWith(staticPath) && staticPath.length() > score) {
                path = staticPath;
                score = path.length();
            }
        }

        return path;
    }

    @Nullable
    @Override
    public String getDynamicPathFromStaticPath(@Nonnull String filePath) {
        return super.getDynamicPathFromStaticPath(filePath);
    }

    @Nullable
    @Override
    public String getDynamicRoot() {
        return super.getDynamicRoot();
    }

    @Nullable
    @Override
    public String getStaticRoot() {
        return super.getStaticRoot();
    }

    Set<String> dynamicPaths = set(), staticPaths = set();

    @Override
    public void setEndpointGenerator(EndpointGenerator generator) {
        if (generator == null) {
            LOG.error("Got null endpoint generator. We shouldn't be here.");
            assert false : "Shouldn't have gotten here.";
            return;
        }

        for (Endpoint endpoint : generator) {
            if (endpoint != null) {
                dynamicPaths.add(endpoint.getUrlPath());
                staticPaths.add(endpoint.getFilePath());
            }
        }
    }
}
