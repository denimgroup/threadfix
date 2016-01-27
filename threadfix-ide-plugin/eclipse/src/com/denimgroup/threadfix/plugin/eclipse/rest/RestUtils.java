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
package com.denimgroup.threadfix.plugin.eclipse.rest;

import com.denimgroup.threadfix.plugin.eclipse.util.Constants;
import com.denimgroup.threadfix.plugin.eclipse.util.EclipsePropertiesManager;
import com.denimgroup.threadfix.remote.HttpRestUtils;
import com.denimgroup.threadfix.remote.response.RestResponse;

public class RestUtils {
	
    // the UI validation should ensure that the /rest part of the returned url is valid.
    public static RestResponse<Object> test(String url) {
        return test(url, "test");
    }

    // the UI validation should ensure that the /rest part of the returned url is valid.
    public static RestResponse<Object> test(String url, String key) {
    	HttpRestUtils utils = new HttpRestUtils(EclipsePropertiesManager.INSTANCE);
        return utils.httpGet(Constants.MARKERS_URL_SEGMENT + "0");
    }

}
