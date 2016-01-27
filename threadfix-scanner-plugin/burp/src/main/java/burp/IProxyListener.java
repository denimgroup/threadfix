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
 * @(#)IProxyListener.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerProxyListener()</code> to register a
 * Proxy listener. The listener will be notified of requests and responses being
 * processed by the Proxy tool. Extensions can perform custom analysis or
 * modification of these messages, and control in-UI message interception, by
 * registering a proxy listener.
 */
public interface IProxyListener
{
    /**
     * This method is invoked when an HTTP message is being processed by the
     * Proxy.
     *
     * @param messageIsRequest Indicates whether the HTTP message is a request
     * or a response.
     * @param message An
     * <code>IInterceptedProxyMessage</code> object that extensions can use to
     * query and update details of the message, and control whether the message
     * should be intercepted and displayed to the user for manual review or
     * modification.
     */
    void processProxyMessage(
            boolean messageIsRequest,
            IInterceptedProxyMessage message);
}
