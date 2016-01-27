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
 * @(#)IMenuItemHandler.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerMenuItem()</code> to register a custom
 * context menu item.
 *
 * @deprecated Use
 * <code>IContextMenuFactory</code> instead.
 */
@Deprecated
public interface IMenuItemHandler
{
    /**
     * This method is invoked by Burp Suite when the user clicks on a custom
     * menu item which the extension has registered with Burp.
     *
     * @param menuItemCaption The caption of the menu item which was clicked.
     * This parameter enables extensions to provide a single implementation
     * which handles multiple different menu items.
     * @param messageInfo Details of the HTTP message(s) for which the context
     * menu was displayed.
     */
    void menuItemClicked(
            String menuItemCaption,
            IHttpRequestResponse[] messageInfo);
}
