////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface PathCleaner {

    @Nullable
	String cleanStaticPath(@Nonnull String filePath);

    @Nullable
	String cleanDynamicPath(@Nonnull String urlPath);

    /**
     * Optional method. Classes wishing to skip this method should return filePath.
     * @param filePath
     * @return dynamic URL
     */
    @Nullable
    String getDynamicPathFromStaticPath(@Nonnull String filePath);

    @Nullable
	String getDynamicRoot();

    @Nullable
	String getStaticRoot();

    void setEndpointGenerator(EndpointGenerator generator);
}
