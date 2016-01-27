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
 * @(#)IScannerCheck.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.List;

/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerScannerCheck()</code> to register a
 * custom Scanner check. When performing scanning, Burp will ask the check to
 * perform active or passive scanning on the base request, and report any
 * Scanner issues that are identified.
 */
public interface IScannerCheck
{
    /**
     * The Scanner invokes this method for each base request / response that is
     * passively scanned. <b>Note:</b> Extensions should not only analyze the
     * HTTP messages provided during passive scanning, and should not make any
     * new HTTP requests of their own.
     *
     * @param baseRequestResponse The base HTTP request / response that should
     * be passively scanned.
     * @return A list of
     * <code>IScanIssue</code> objects, or
     * <code>null</code> if no issues are identified.
     */
    List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse);

    /**
     * The Scanner invokes this method for each insertion point that is actively
     * scanned. Extensions may issue HTTP requests as required to carry out
     * active scanning, and should use the
     * <code>IScannerInsertionPoint</code> object provided to build scan
     * requests for particular payloads. <b>Note:</b> Extensions are responsible
     * for ensuring that attack payloads are suitably encoded within requests
     * (for example, by URL-encoding relevant metacharacters in the URL query
     * string). Encoding is not automatically carried out by the
     * <code>IScannerInsertionPoint</code>, because this would prevent Scanner
     * checks from testing for certain input filter bypasses. Extensions should
     * query the
     * <code>IScannerInsertionPoint</code> to determine its type, and apply any
     * encoding that may be appropriate.
     *
     * @param baseRequestResponse The base HTTP request / response that should
     * be actively scanned.
     * @param insertionPoint An
     * <code>IScannerInsertionPoint</code> object that can be queried to obtain
     * details of the insertion point being tested, and can be used to build
     * scan requests for particular payloads.
     * @return A list of
     * <code>IScanIssue</code> objects, or
     * <code>null</code> if no issues are identified.
     */
    List<IScanIssue> doActiveScan(
            IHttpRequestResponse baseRequestResponse,
            IScannerInsertionPoint insertionPoint);

    /**
     * The Scanner invokes this method when the custom Scanner check has
     * reported multiple issues for the same URL path. This can arise either
     * because there are multiple distinct vulnerabilities, or because the same
     * (or a similar) request has been scanned more than once. The custom check
     * should determine whether the issues are duplicates. In most cases, where
     * a check uses distinct issue names or descriptions for distinct issues,
     * the consolidation process will simply be a matter of comparing these
     * features for the two issues.
     *
     * @param existingIssue An issue that was previously reported by this
     * Scanner check.
     * @param newIssue An issue at the same URL path that has been newly
     * reported by this Scanner check.
     * @return An indication of which issue(s) should be reported in the main
     * Scanner results. The method should return
     * <code>-1</code> to report the existing issue only,
     * <code>0</code> to report both issues, and
     * <code>1</code> to report the new issue only.
     */
    int consolidateDuplicateIssues(
            IScanIssue existingIssue,
            IScanIssue newIssue);
}
