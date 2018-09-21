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
 * @(#)IHttpRequestResponseWithMarkers.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.List;

/**
 * This interface is used for an
 * <code>IHttpRequestResponse</code> object that has had markers applied.
 * Extensions can create instances of this interface using
 * <code>IBurpExtenderCallbacks.applyMarkers()</code>, or provide their own
 * implementation. Markers are used in various situations, such as specifying
 * Intruder payload positions, Scanner insertion points, and highlights in
 * Scanner issues.
 */
public interface IHttpRequestResponseWithMarkers extends IHttpRequestResponse
{
    /**
     * This method returns the details of the request markers.
     *
     * @return A list of index pairs representing the offsets of markers for the
     * request message. Each item in the list is an int[2] array containing the
     * start and end offsets for the marker. The method may return
     * <code>null</code> if no request markers are defined.
     */
    List<int[]> getRequestMarkers();

    /**
     * This method returns the details of the response markers.
     *
     * @return A list of index pairs representing the offsets of markers for the
     * response message. Each item in the list is an int[2] array containing the
     * start and end offsets for the marker. The method may return
     * <code>null</code> if no response markers are defined.
     */
    List<int[]> getResponseMarkers();
}
