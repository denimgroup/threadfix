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
package com.servicenow.grcpolicyservice;

import javax.xml.bind.annotation.*;

/**
 * @author zabdisubhan
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "grc_policy_name" })
@XmlRootElement(name = "submit", namespace = "http://www.service-now.com/GRCPolicyService")
public class SubmitPolicy {

    private static final String GRC_POLICY_SERVICE = "http://www.service-now.com/GRCPolicyService";

    @XmlElement(required = true, namespace = GRC_POLICY_SERVICE)
    private String grc_policy_name;

    public String getGrc_policy_name() {
        return grc_policy_name;
    }

    public void setGrc_policy_name(String grc_policy_name) {
        this.grc_policy_name = grc_policy_name;
    }
}
