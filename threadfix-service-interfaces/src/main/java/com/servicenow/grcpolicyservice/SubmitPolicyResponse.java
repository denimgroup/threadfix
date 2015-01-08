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

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "link", "grc_policy_sys_id", "status_message", "status", "grc_policy_number" })
@XmlRootElement(name = "submitResponse", namespace = "http://www.service-now.com/GRCPolicyService")
public class SubmitPolicyResponse {

    private static final String GRC_POLICY_SERVICE = "http://www.service-now.com/GRCPolicyService";

    @XmlElement(required = true, namespace = GRC_POLICY_SERVICE)
    private String link;

    @XmlElement(required = true, namespace = GRC_POLICY_SERVICE)
    private String grc_policy_sys_id;

    @XmlElement(required = true, namespace = GRC_POLICY_SERVICE)
    private String status_message;

    @XmlElement(required = true, namespace = GRC_POLICY_SERVICE)
    private String status;

    @XmlElement(required = true, namespace = GRC_POLICY_SERVICE)
    private String grc_policy_number;

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public String getGrc_policy_sys_id() {
        return grc_policy_sys_id;
    }

    public void setGrc_policy_sys_id(String grc_policy_sys_id) {
        this.grc_policy_sys_id = grc_policy_sys_id;
    }

    public String getStatus_message() {
        return status_message;
    }

    public void setStatus_message(String status_message) {
        this.status_message = status_message;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getGrc_policy_number() {
        return grc_policy_number;
    }

    public void setGrc_policy_number(String grc_policy_number) {
        this.grc_policy_number = grc_policy_number;
    }
}
