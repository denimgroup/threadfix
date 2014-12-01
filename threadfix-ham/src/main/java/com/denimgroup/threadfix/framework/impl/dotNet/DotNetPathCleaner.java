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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.framework.engine.cleaner.PathCleaner;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Created by mac on 7/21/14.
 */
public class DotNetPathCleaner implements PathCleaner {

    public static String cleanStringFromCode(String input) {
        return input.replaceAll("\\{[^\\}]*\\}", "{variable}");
    }

    public static String cleanStringFromScan(String input) {
        return input.replaceAll("\\/[0-9]+$","/{variable}").replaceAll("\\/[0-9]+\\/", "/{variable}/");
    }

    @Nullable
    @Override
    public String cleanStaticPath(@Nonnull String filePath) {
        return filePath;
    }

    @Nullable
    @Override
    public String cleanDynamicPath(@Nonnull String urlPath) {
        return cleanStringFromScan(urlPath);
    }

    @Nullable
    @Override
    public String getDynamicPathFromStaticPath(@Nonnull String filePath) {
        return filePath;
    }

    @Nullable
    @Override
    public String getDynamicRoot() {
        return null;
    }

    @Override
    public void setEndpointGenerator(EndpointGenerator generator) {
        // we don't care about this
    }

    @Nullable
    @Override
    public String getStaticRoot() {
        return null;
    }
}
