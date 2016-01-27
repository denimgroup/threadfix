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
 * @(#)IResponseInfo.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.List;

/**
 * This interface is used to retrieve key details about an HTTP response.
 * Extensions can obtain an
 * <code>IResponseInfo</code> object for a given response by calling
 * <code>IExtensionHelpers.analyzeResponse()</code>.
 */
public interface IResponseInfo
{
    /**
     * This method is used to obtain the HTTP headers contained in the response.
     *
     * @return The HTTP headers contained in the response.
     */
    List<String> getHeaders();

    /**
     * This method is used to obtain the offset within the response where the
     * message body begins.
     *
     * @return The offset within the response where the message body begins.
     */
    int getBodyOffset();

    /**
     * This method is used to obtain the HTTP status code contained in the
     * response.
     *
     * @return The HTTP status code contained in the response.
     */
    short getStatusCode();

    /**
     * This method is used to obtain details of the HTTP cookies set in the
     * response.
     *
     * @return A list of <code>ICookie</code> objects representing the cookies
     * set in the response, if any.
     */
    List<ICookie> getCookies();

    /**
     * This method is used to obtain the MIME type of the response, as stated in
     * the HTTP headers.
     *
     * @return A textual label for the stated MIME type, or an empty String if
     * this is not known or recognized. The possible labels are the same as
     * those used in the main Burp UI.
     */
    String getStatedMimeType();

    /**
     * This method is used to obtain the MIME type of the response, as inferred
     * from the contents of the HTTP message body.
     *
     * @return A textual label for the inferred MIME type, or an empty String if
     * this is not known or recognized. The possible labels are the same as
     * those used in the main Burp UI.
     */
    String getInferredMimeType();
}
