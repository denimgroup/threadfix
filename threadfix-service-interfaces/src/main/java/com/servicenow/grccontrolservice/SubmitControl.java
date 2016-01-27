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
package com.servicenow.grccontrolservice;

import javax.xml.bind.annotation.*;

/**
 * @author zabdisubhan
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "grc_control_name", "grc_control_u_cwe_id", "grc_control_u_vulnerability_id",
"grc_control_u_vulnerability_url", "grc_control_u_correlation_id", "grc_control_policy_sys_id"})
@XmlRootElement(name = "submit", namespace = "http://www.service-now.com/GRCControlService")
public class SubmitControl {

    private static final String GRC_CONTROL_SERVICE = "http://www.service-now.com/GRCControlService";

    @XmlElement(required = true, namespace = GRC_CONTROL_SERVICE)
    private String grc_control_name;

    @XmlElement(required = true, namespace = GRC_CONTROL_SERVICE)
    private Integer grc_control_u_cwe_id;

    @XmlElement(required = true, namespace = GRC_CONTROL_SERVICE)
    private Integer grc_control_u_vulnerability_id;

    @XmlElement(required = true, namespace = GRC_CONTROL_SERVICE)
    private String grc_control_u_vulnerability_url;

    @XmlElement(required = true, namespace = GRC_CONTROL_SERVICE)
    private Integer grc_control_u_correlation_id;

    @XmlElement(required = true, namespace = GRC_CONTROL_SERVICE)
    private String grc_control_policy_sys_id;

    public String getGrc_control_name() {
        return grc_control_name;
    }

    public void setGrc_control_name(String grc_control_name) {
        this.grc_control_name = grc_control_name;
    }

    public Integer getGrc_control_u_cwe_id() {
        return grc_control_u_cwe_id;
    }

    public void setGrc_control_u_cwe_id(Integer grc_control_u_cwe_id) {
        this.grc_control_u_cwe_id = grc_control_u_cwe_id;
    }

    public Integer getGrc_control_u_vulnerability_id() {
        return grc_control_u_vulnerability_id;
    }

    public void setGrc_control_u_vulnerability_id(Integer grc_control_u_vulnerability_id) {
        this.grc_control_u_vulnerability_id = grc_control_u_vulnerability_id;
    }

    public String getGrc_control_u_vulnerability_url() {
        return grc_control_u_vulnerability_url;
    }

    public void setGrc_control_u_vulnerability_url(String grc_control_u_vulnerability_url) {
        this.grc_control_u_vulnerability_url = grc_control_u_vulnerability_url;
    }

    public Integer getGrc_control_u_correlation_id() {
        return grc_control_u_correlation_id;
    }

    public void setGrc_control_u_correlation_id(Integer grc_control_u_correlation_id) {
        this.grc_control_u_correlation_id = grc_control_u_correlation_id;
    }

    public String getGrc_control_policy_sys_id() {
        return grc_control_policy_sys_id;
    }

    public void setGrc_control_policy_sys_id(String grc_control_policy_sys_id) {
        this.grc_control_policy_sys_id = grc_control_policy_sys_id;
    }
}
