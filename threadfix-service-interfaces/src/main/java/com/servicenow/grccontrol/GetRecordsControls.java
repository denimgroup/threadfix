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
package com.servicenow.grccontrol;

import javax.xml.bind.annotation.*;

/**
 * @author zabdisubhan
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "assessment_number", "__limit", "__exclude_columns" })
@XmlRootElement(name = "getRecords", namespace = "http://www.service-now.com/u_grc_policy_control_view")
public class GetRecordsControls {

    private static final String GRC_CONTROL = "http://www.service-now.com/u_grc_policy_control_view";

    @XmlElement(namespace = GRC_CONTROL)
    private String assessment_number;

    @XmlElement(namespace = GRC_CONTROL)
    private Integer __limit;

    @XmlElement(namespace = GRC_CONTROL)
    private String __exclude_columns;


    public String getAssessment_number() {
        return assessment_number;
    }

    public void setAssessment_number(String assessment_number) {
        this.assessment_number = assessment_number;
    }

    public Integer get__limit() {
        return __limit;
    }

    public void set__limit(Integer __limit) {
        this.__limit = __limit;
    }

    public String get__exclude_columns() {
        return __exclude_columns;
    }

    public void set__exclude_columns(String __exclude_columns) {
        this.__exclude_columns = __exclude_columns;
    }
}
