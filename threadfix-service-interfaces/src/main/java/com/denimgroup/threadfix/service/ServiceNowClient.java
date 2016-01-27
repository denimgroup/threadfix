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

package com.denimgroup.threadfix.service;

import com.servicenow.grccontrol.GetRecordsControlsResponse;
import com.servicenow.grcpolicy.GetRecordsPoliciesResponse;
import com.servicenow.grccontrolservice.SubmitControlResponse;
import com.servicenow.grcpolicyservice.SubmitPolicyResponse;
import org.springframework.ws.client.WebServiceIOException;

/**
 * @author zabdisubhan
 *
 */
public interface ServiceNowClient {

    void configure(String uri, String username, String password);

    SubmitPolicyResponse getSubmitPolicyResponse(String policyName) throws WebServiceIOException;

    GetRecordsPoliciesResponse getGetRecordsPoliciesResponse(String encodedQuery,
                                                                    String excludeColumns, Integer limit)
                                                                    throws WebServiceIOException;

    SubmitControlResponse getSubmitControlResponse(String name, Integer cweId, Integer vulnId, String vulnUrl,
                                                   Integer correlationId, String policySysId) throws WebServiceIOException;

    GetRecordsControlsResponse getRecordsControlsResponse(String assessmentNumber,
                                                          String excludeColumns) throws WebServiceIOException;
}
