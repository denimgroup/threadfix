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

package burp;

/*
 * @(#)ICookie.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.Date;

/**
 * This interface is used to hold details about an HTTP cookie.
 */
public interface ICookie
{
    /**
     * This method is used to retrieve the domain for which the cookie is in
     * scope.
     *
     * @return The domain for which the cookie is in scope. <b>Note:</b> For
     * cookies that have been analyzed from responses (by calling
     * <code>IExtensionHelpers.analyzeResponse()</code> and then
     * <code>IResponseInfo.getCookies()</code>, the domain will be
     * <code>null</code> if the response did not explicitly set a domain
     * attribute for the cookie.
     */
    String getDomain();

    /**
     * This method is used to retrieve the expiration time for the cookie.
     *
     * @return The expiration time for the cookie, or
     * <code>null</code> if none is set (i.e., for non-persistent session
     * cookies).
     */
    Date getExpiration();

    /**
     * This method is used to retrieve the name of the cookie.
     * 
     * @return The name of the cookie.
     */
    String getName();

    /**
     * This method is used to retrieve the value of the cookie.
     * @return The value of the cookie.
     */
    String getValue();
}
