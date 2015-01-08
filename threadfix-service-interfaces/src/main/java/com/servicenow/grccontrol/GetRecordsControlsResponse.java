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
package com.servicenow.grccontrol;

import javax.xml.bind.annotation.*;
import java.util.List;

/**
 * @author zabdisubhan
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "getRecordsResult" })
@XmlRootElement(name = "getRecordsResponse", namespace = "http://www.service-now.com/u_grc_policy_control_view")
public class GetRecordsControlsResponse {

    private static final String GRC_CONTROL = "http://www.service-now.com/u_grc_policy_control_view";

    @XmlElement(namespace = GRC_CONTROL)
    private List<GetRecordsControlsResult> getRecordsResult;


    public List<GetRecordsControlsResult> getGetRecordsResult() {
        return getRecordsResult;
    }

    public void setGetRecordsResult(List<GetRecordsControlsResult> getRecordsResult) {
        this.getRecordsResult = getRecordsResult;
    }
}
