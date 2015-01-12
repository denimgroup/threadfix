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
 * @(#)ISessionHandlingAction.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerSessionHandlingAction()</code> to
 * register a custom session handling custombutton. Each registered custombutton will be
 * available within the session handling rule UI for the user to select as a
 * rule custombutton. Users can choose to invoke an custombutton directly in its own right,
 * or following execution of a macro.
 */
public interface ISessionHandlingAction
{
    /**
     * This method is used by Burp to obtain the name of the session handling
     * custombutton. This will be displayed as an option within the session handling
     * rule editor when the user selects to execute an extension-provided
     * custombutton.
     *
     * @return The name of the custombutton.
     */
    String getActionName();

    /**
     * This method is invoked when the session handling custombutton should be
     * executed. This may happen as an custombutton in its own right, or as a
     * sub-custombutton following execution of a macro.
     *
     * @param currentRequest The base request that is currently being processed.
     * The custombutton can query this object to obtain details about the base
     * request. It can issue additional requests of its own if necessary, and
     * can use the setter methods on this object to update the base request.
     * @param macroItems If the custombutton is invoked following execution of a
     * macro, this parameter contains the result of executing the macro.
     * Otherwise, it is
     * <code>null</code>. Actions can use the details of the macro items to
     * perform custom analysis of the macro to derive values of non-standard
     * session handling tokens, etc.
     */
    void performAction(
            IHttpRequestResponse currentRequest,
            IHttpRequestResponse[] macroItems);
}
