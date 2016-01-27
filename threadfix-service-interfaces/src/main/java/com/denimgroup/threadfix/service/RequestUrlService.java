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

package com.denimgroup.threadfix.service;

import javax.servlet.http.HttpServletRequest;

public interface RequestUrlService {

	/**
	 * Returns the string of the base URL queried to the HTTP Servlet
	 * Like: https://hostname:8443/threadfix
	 * Such as the controllers paths appended to this string would make a valid URL
	 * The port number doesn't appear (like in web browsers) if it's standard like 80 or 443
	 */
	public String getBaseUrlFromRequest(HttpServletRequest request);

}
