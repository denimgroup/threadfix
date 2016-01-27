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
package com.servicenow.grcpolicy;

import javax.xml.bind.annotation.*;

/**
 * @author zabdisubhan
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "__encoded_query", "__limit", "__exclude_columns" })
@XmlRootElement(name = "getRecords", namespace = "http://www.service-now.com/grc_policy")
public class GetRecordsPolicies {

    private static final String GRC_POLICY = "http://www.service-now.com/grc_policy";

    @XmlElement(namespace = GRC_POLICY)
    private String __encoded_query;

    @XmlElement(namespace = GRC_POLICY)
    private Integer __limit;

    @XmlElement(namespace = GRC_POLICY)
    private String __exclude_columns;


    public String get__encoded_query() {
        return __encoded_query;
    }

    public void set__encoded_query(String __encoded_query) {
        this.__encoded_query = __encoded_query;
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
