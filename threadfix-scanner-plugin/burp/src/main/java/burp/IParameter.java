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
 * @(#)IParameter.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to hold details about an HTTP request parameter.
 */
public interface IParameter
{
    /**
     * Used to indicate a parameter within the URL query string.
     */
    static final byte PARAM_URL = 0;
    /**
     * Used to indicate a parameter within the message body.
     */
    static final byte PARAM_BODY = 1;
    /**
     * Used to indicate an HTTP cookie.
     */
    static final byte PARAM_COOKIE = 2;
    /**
     * Used to indicate an item of data within an XML structure.
     */
    static final byte PARAM_XML = 3;
    /**
     * Used to indicate the value of a tag attribute within an XML structure.
     */
    static final byte PARAM_XML_ATTR = 4;
    /**
     * Used to indicate the value of a parameter attribute within a multi-part
     * message body (such as the name of an uploaded file).
     */
    static final byte PARAM_MULTIPART_ATTR = 5;
    /**
     * Used to indicate an item of data within a JSON structure.
     */
    static final byte PARAM_JSON = 6;

    /**
     * This method is used to retrieve the parameter type.
     *
     * @return The parameter type. The available types are defined within this
     * interface.
     */
    byte getType();

    /**
     * This method is used to retrieve the parameter name.
     *
     * @return The parameter name.
     */
    String getName();

    /**
     * This method is used to retrieve the parameter value.
     *
     * @return The parameter value.
     */
    String getValue();

    /**
     * This method is used to retrieve the start offset of the parameter name
     * within the HTTP request.
     *
     * @return The start offset of the parameter name within the HTTP request,
     * or -1 if the parameter is not associated with a specific request.
     */
    int getNameStart();

    /**
     * This method is used to retrieve the end offset of the parameter name
     * within the HTTP request.
     *
     * @return The end offset of the parameter name within the HTTP request, or
     * -1 if the parameter is not associated with a specific request.
     */
    int getNameEnd();

    /**
     * This method is used to retrieve the start offset of the parameter value
     * within the HTTP request.
     *
     * @return The start offset of the parameter value within the HTTP request,
     * or -1 if the parameter is not associated with a specific request.
     */
    int getValueStart();

    /**
     * This method is used to retrieve the end offset of the parameter value
     * within the HTTP request.
     *
     * @return The end offset of the parameter value within the HTTP request, or
     * -1 if the parameter is not associated with a specific request.
     */
    int getValueEnd();
}
