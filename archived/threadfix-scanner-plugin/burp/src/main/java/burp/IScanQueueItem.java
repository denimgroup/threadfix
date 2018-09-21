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
 * @(#)IScanQueueItem.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

/**
 * This interface is used to retrieve details of items in the Burp Scanner
 * active scan queue. Extensions can obtain references to scan queue items by
 * calling
 * <code>IBurpExtenderCallbacks.doActiveScan()</code>.
 */
public interface IScanQueueItem
{
    /**
     * This method returns a description of the status of the scan queue item.
     *
     * @return A description of the status of the scan queue item.
     */
    String getStatus();

    /**
     * This method returns an indication of the percentage completed for the
     * scan queue item.
     *
     * @return An indication of the percentage completed for the scan queue
     * item.
     */
    byte getPercentageComplete();

    /**
     * This method returns the number of requests that have been made for the
     * scan queue item.
     *
     * @return The number of requests that have been made for the scan queue
     * item.
     */
    int getNumRequests();

    /**
     * This method returns the number of network errors that have occurred for
     * the scan queue item.
     *
     * @return The number of network errors that have occurred for the scan
     * queue item.
     */
    int getNumErrors();

    /**
     * This method returns the number of attack insertion points being used for
     * the scan queue item.
     *
     * @return The number of attack insertion points being used for the scan
     * queue item.
     */
    int getNumInsertionPoints();

    /**
     * This method allows the scan queue item to be canceled.
     */
    void cancel();

    /**
     * This method returns details of the issues generated for the scan queue
     * item. <b>Note:</b> different items within the scan queue may contain
     * duplicated versions of the same issues - for example, if the same request
     * has been scanned multiple times. Duplicated issues are consolidated in
     * the main view of scan results. Extensions can register an
     * <code>IScannerListener</code> to get details only of unique, newly
     * discovered Scanner issues post-consolidation.
     *
     * @return Details of the issues generated for the scan queue item.
     */
    IScanIssue[] getIssues();
}
