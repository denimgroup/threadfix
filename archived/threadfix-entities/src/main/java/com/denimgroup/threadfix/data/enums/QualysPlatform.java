////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

package com.denimgroup.threadfix.data.enums;

import java.util.List;
import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by zabdisubhan on 9/22/14.
 */

public enum QualysPlatform {
    US_1("US Platform 1", "https://qualysapi.qualys.com"),
    US_2("US Platform 2", "https://qualysapi.qg2.apps.qualys.com"),
    EU("EU Platform", "https://qualysapi.qualys.eu");

    private String platformName;
    private String url;

    public String getPlatformName() {
        return this.platformName;
    }

    public String getUrl() {
        return this.url;
    }

    public static List<String> getPlatforms() {
       List<String> platforms = list();

        for (QualysPlatform platform : QualysPlatform.values()){
            platforms.add(platform.getPlatformName());
        }

        return platforms;
    }

    public static QualysPlatform getPlatform(String keyword) {
        for (QualysPlatform t: values()) {
            if (keyword.equalsIgnoreCase(t.getPlatformName())) {
                return t;
            }
        }
        return null;
    }

    private QualysPlatform(String platformName, String url) {
        this.platformName = platformName;
        this.url = url;
    }
}
