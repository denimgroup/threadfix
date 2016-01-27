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

package com.denimgroup.threadfix.cli;

import com.denimgroup.threadfix.properties.PropertiesManager;
import com.denimgroup.threadfix.remote.HttpRestUtils;
import com.google.gson.Gson;
import org.apache.commons.lang.RandomStringUtils;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/21/13
 * Time: 4:00 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestPropertiesManager extends PropertiesManager {

    public static final String URL = "http://localhost:8082/rest";
    public static final String API_KEY = "xZ32iTkKAVVBUio2cR81mgqpLRw19EMAvxmkLHvkM";

    @Override
    public String getUrl() {
        return URL;
    }

    @Override
    public String getKey() {
        return API_KEY;
    }

    public static Object getJSONObject(String responseContents) {
        return new Gson().fromJson(responseContents, Object.class);
    }

    public static PropertiesManager getPropertiesManager() {
        PropertiesManager manager = new PropertiesManager();
        manager.setMemoryKey(URL);
        manager.setKey(API_KEY);
        return manager;
    }

    public static HttpRestUtils getRestUtils() {
        return new HttpRestUtils(getPropertiesManager());
    }

    public static String getName() {
        return getRandomString(20);
    }

    public static String getRandomString(int length) {
        return RandomStringUtils.random(length, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    }
}
