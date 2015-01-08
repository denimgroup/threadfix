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
package com.servicenow.grcpolicy;

import javax.xml.bind.annotation.*;

/**
 * @author zabdisubhan
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "number", "short_description", "sys_id", "u_type" })
@XmlRootElement(name = "getRecordsResult", namespace = "http://www.service-now.com/grc_policy")
public class GetRecordsPoliciesResult {

    private static final String GRC_POLICY = "http://www.service-now.com/grc_policy";

    @XmlElement(namespace = GRC_POLICY)
    private String number;

    @XmlElement(namespace = GRC_POLICY)
    private String short_description;

    @XmlElement(namespace = GRC_POLICY)
    private String sys_id;

    @XmlElement(namespace = GRC_POLICY)
    private String u_type;

    public String getNumber() {
        return number;
    }

    public void setNumber(String number) {
        this.number = number;
    }

    public String getShort_description() {
        return short_description;
    }

    public void setShort_description(String short_description) {
        this.short_description = short_description;
    }

    public String getSys_id() {
        return sys_id;
    }

    public void setSys_id(String sys_id) {
        this.sys_id = sys_id;
    }

    public String getU_type() {
        return u_type;
    }

    public void setU_type(String u_type) {
        this.u_type = u_type;
    }
}
