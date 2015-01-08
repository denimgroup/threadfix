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
 * @(#)IInterceptedProxyMessage.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.net.InetAddress;

/**
 * This interface is used to represent an HTTP message that has been intercepted
 * by Burp Proxy. Extensions can register an
 * <code>IProxyListener</code> to receive details of proxy messages using this
 * interface. *
 */
public interface IInterceptedProxyMessage
{
    /**
     * This custombutton causes Burp Proxy to follow the current interception rules to
     * determine the appropriate custombutton to take for the message.
     */
    static final int ACTION_FOLLOW_RULES = 0;
    /**
     * This custombutton causes Burp Proxy to present the message to the user for
     * manual review or modification.
     */
    static final int ACTION_DO_INTERCEPT = 1;
    /**
     * This custombutton causes Burp Proxy to forward the message to the remote server
     * or client, without presenting it to the user.
     */
    static final int ACTION_DONT_INTERCEPT = 2;
    /**
     * This custombutton causes Burp Proxy to drop the message.
     */
    static final int ACTION_DROP = 3;
    /**
     * This custombutton causes Burp Proxy to follow the current interception rules to
     * determine the appropriate custombutton to take for the message, and then make a
     * second call to processProxyMessage.
     */
    static final int ACTION_FOLLOW_RULES_AND_REHOOK = 0x10;
    /**
     * This custombutton causes Burp Proxy to present the message to the user for
     * manual review or modification, and then make a second call to
     * processProxyMessage.
     */
    static final int ACTION_DO_INTERCEPT_AND_REHOOK = 0x11;
    /**
     * This custombutton causes Burp Proxy to skip user interception, and then make a
     * second call to processProxyMessage.
     */
    static final int ACTION_DONT_INTERCEPT_AND_REHOOK = 0x12;

    /**
     * This method retrieves a unique reference number for this
     * request/response.
     *
     * @return An identifier that is unique to a single request/response pair.
     * Extensions can use this to correlate details of requests and responses
     * and perform processing on the response message accordingly.
     */
    int getMessageReference();

    /**
     * This method retrieves details of the intercepted message.
     *
     * @return An <code>IHttpRequestResponse</code> object containing details of
     * the intercepted message.
     */
    IHttpRequestResponse getMessageInfo();

    /**
     * This method retrieves the currently defined interception custombutton. The
     * default custombutton is
     * <code>ACTION_FOLLOW_RULES</code>. If multiple proxy listeners are
     * registered, then other listeners may already have modified the
     * interception custombutton before it reaches the current listener. This method
     * can be used to determine whether this has occurred.
     *
     * @return The currently defined interception custombutton. Possible values are
     * defined within this interface.
     */
    int getInterceptAction();

    /**
     * This method is used to update the interception custombutton.
     *
     * @param interceptAction The new interception custombutton. Possible values are
     * defined within this interface.
     */
    void setInterceptAction(int interceptAction);

    /**
     * This method retrieves the name of the Burp Proxy listener that is
     * processing the intercepted message.
     *
     * @return The name of the Burp Proxy listener that is processing the
     * intercepted message. The format is the same as that shown in the Proxy
     * Listeners UI - for example, "127.0.0.1:8080".
     */
    String getListenerInterface();

    /**
     * This method retrieves the client IP address from which the request for
     * the intercepted message was received.
     *
     * @return The client IP address from which the request for the intercepted
     * message was received.
     */
    InetAddress getClientIpAddress();
}
