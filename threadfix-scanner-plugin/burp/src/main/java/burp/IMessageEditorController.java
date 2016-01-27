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
 * @(#)IMessageEditorController.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

/**
 * This interface is used by an
 * <code>IMessageEditor</code> to obtain details about the currently displayed
 * message. Extensions that create instances of Burp's HTTP message editor can
 * optionally provide an implementation of
 * <code>IMessageEditorController</code>, which the editor will invoke when it
 * requires further information about the current message (for example, to send
 * it to another Burp tool). Extensions that provide custom editor tabs via an
 * <code>IMessageEditorTabFactory</code> will receive a reference to an
 * <code>IMessageEditorController</code> object for each tab instance they
 * generate, which the tab can invoke if it requires further information about
 * the current message.
 */
public interface IMessageEditorController
{
    /**
     * This method is used to retrieve the HTTP service for the current message.
     *
     * @return The HTTP service for the current message.
     */
    IHttpService getHttpService();

    /**
     * This method is used to retrieve the HTTP request associated with the
     * current message (which may itself be a response).
     *
     * @return The HTTP request associated with the current message.
     */
    byte[] getRequest();

    /**
     * This method is used to retrieve the HTTP response associated with the
     * current message (which may itself be a request).
     *
     * @return The HTTP response associated with the current message.
     */
    byte[] getResponse();
}
