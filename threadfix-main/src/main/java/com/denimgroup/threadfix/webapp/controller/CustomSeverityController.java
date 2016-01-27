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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.SeverityFilter;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.SeverityFilterService;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

/**
 * Created by mcollins on 7/29/15.
 */
@Controller
public class CustomSeverityController {

    @Autowired
    private SeverityFilterService severityFilterService;
    @Autowired
    private GenericSeverityService genericSeverityService;

    @RequestMapping("/severities")
    public String index() {
        if (EnterpriseTest.isEnterprise()) {
            return "customize/threadfixSeverity/enterprise";
        } else {
            return "customize/threadfixSeverity/community";
        }
    }

    @RequestMapping(value = "/severities/list", produces = "application/json")
    @JsonView(AllViews.TableRow.class)
    @ResponseBody
    public RestResponse<Map<String, Object>> list() {
        SeverityFilter globalFilter = severityFilterService.loadFilter(-1, -1);

        if (globalFilter == null) {
            globalFilter = new SeverityFilter();
            globalFilter.setEnabled(false);
            severityFilterService.save(globalFilter, -1, -1);
        }

        return success(map(
                    "genericSeverities", genericSeverityService.loadAll(),
                    "globalSeverityFilter", globalFilter
                ));
    }

}
