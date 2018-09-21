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

package burp;

/*
 * @(#)IRequestInfo.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.net.URL;
import java.util.List;

/**
 * This interface is used to retrieve key details about an HTTP request.
 * Extensions can obtain an
 * <code>IRequestInfo</code> object for a given request by calling
 * <code>IExtensionHelpers.analyzeRequest()</code>.
 */
public interface IRequestInfo
{
    /**
     * Used to indicate that there is no content.
     */
    static final byte CONTENT_TYPE_NONE = 0;
    /**
     * Used to indicate URL-encoded content.
     */
    static final byte CONTENT_TYPE_URL_ENCODED = 1;
    /**
     * Used to indicate multi-part content.
     */
    static final byte CONTENT_TYPE_MULTIPART = 2;
    /**
     * Used to indicate XML content.
     */
    static final byte CONTENT_TYPE_XML = 3;
    /**
     * Used to indicate JSON content.
     */
    static final byte CONTENT_TYPE_JSON = 4;
    /**
     * Used to indicate AMF content.
     */
    static final byte CONTENT_TYPE_AMF = 5;
    /**
     * Used to indicate unknown content.
     */
    static final byte CONTENT_TYPE_UNKNOWN = -1;

    /**
     * This method is used to obtain the HTTP method used in the request.
     *
     * @return The HTTP method used in the request.
     */
    String getMethod();

    /**
     * This method is used to obtain the URL in the request.
     *
     * @return The URL in the request.
     */
    URL getUrl();

    /**
     * This method is used to obtain the HTTP headers contained in the request.
     *
     * @return The HTTP headers contained in the request.
     */
    List<String> getHeaders();

    /**
     * This method is used to obtain the parameters contained in the request.
     *
     * @return The parameters contained in the request.
     */
    List<IParameter> getParameters();

    /**
     * This method is used to obtain the offset within the request where the
     * message body begins.
     *
     * @return The offset within the request where the message body begins.
     */
    int getBodyOffset();

    /**
     * This method is used to obtain the content type of the message body.
     *
     * @return An indication of the content type of the message body. Available
     * types are defined within this interface.
     */
    byte getContentType();
}
