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

package org.zaproxy.zap.extension.threadfix;

import org.apache.log4j.Logger;

public class ZapApiPropertiesManager extends AbstractZapPropertiesManager {
    private static final Logger logger = Logger.getLogger(ZapApiPropertiesManager.class);

    private String url = null;
    private String key = null;
    private String appId = null;

    public ZapApiPropertiesManager() {
        this(null, null, null);
    }

    public ZapApiPropertiesManager(String url, String key) {
        this(url, key, null);
    }

    public ZapApiPropertiesManager(String url, String key, String appId) {
        this.url = url;
        this.key = key;
        this.appId = appId;
    }

    @Override
    public String getUrl() {
        return url;
    }

    @Override
    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public void setMemoryUrl(String url) {
        setUrl(url);
    }

    @Override
    public String getKey() {
        return key;
    }

    @Override
    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public void setMemoryKey(String key) {
        setKey(key);
    }

    @Override
    public String getAppId() {
        return appId;
    }

    public void setAppId(String appId) {
        this.appId = appId;
    }
}
