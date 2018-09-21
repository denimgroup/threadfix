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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.FilterDate;
import com.denimgroup.threadfix.data.entities.FilterJsonBlob;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.PolicyStatusService;
import com.denimgroup.threadfix.service.FilterDateService;
import com.denimgroup.threadfix.service.FilterJsonBlobService;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.List;

@Controller
@RequestMapping("/reports/filter/")
public class JsonFilterBlobController {

    private static final SanitizedLogger LOG = new SanitizedLogger(JsonFilterBlobController.class);

    @Autowired
    private FilterJsonBlobService filterJsonBlobService;
    @Autowired
    private FilterDateService filterDateService;
    @Autowired(required = false)
    private PolicyStatusService policyStatusService;

    // Turn Date.getTime() javascript numbers into java.util.Date objects.
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.registerCustomEditor(Date.class, new NumericDatePropertyEditorSupport());
    }

    @RequestMapping(value = "save", method = RequestMethod.POST)
    public @ResponseBody RestResponse<List<FilterJsonBlob>> save(@ModelAttribute FilterJsonBlob filterJsonBlob) {

        FilterJsonBlob dbBlob = filterJsonBlobService.loadByName(filterJsonBlob.getName());

        // If there is active saved filterJson with same name, and this is not updating then return error
        if (dbBlob != null && dbBlob.isActive() && (filterJsonBlob.getId() == null || dbBlob.getId().compareTo(filterJsonBlob.getId()) != 0)) {
            return RestResponse.failure("A filter with that name already exists.");
        } else {
            LOG.info("Saving filter " + filterJsonBlob.getName());
            if (filterJsonBlob.getDefaultTrending()) {
                // Update the old default trending to non-default trending filter
                int filtersNo = filterJsonBlobService.updateDefaultTrendingFilter();
                LOG.info("Number of FilterJsonBlob objects updated to non-default trending report: " + String.valueOf(filtersNo));
            }

            if (dbBlob != null && dbBlob.getPolicy() != null) {
                filterJsonBlob.setPolicy(dbBlob.getPolicy());
            }

            filterJsonBlobService.saveOrUpdate(filterJsonBlob);

            if (policyStatusService != null && filterJsonBlob.getPolicy() != null) {
                policyStatusService.runStatusCheck(filterJsonBlob.getPolicy());
            }

            return RestResponse.success(filterJsonBlobService.loadAllActive());
        }
    }

    @RequestMapping(value = "delete/{filterId}", method = RequestMethod.POST)
    public @ResponseBody RestResponse<List<FilterJsonBlob>> delete(@PathVariable int filterId) {
        FilterJsonBlob blob = filterJsonBlobService.loadById(filterId);
        filterJsonBlobService.markInactive(blob);
        return RestResponse.success(filterJsonBlobService.loadAllActive());
    }

    @JsonView(AllViews.VulnSearchApplications.class)
    @RequestMapping(value = "saveDateRange", method = RequestMethod.POST)
    public @ResponseBody Object saveDateRange(@ModelAttribute FilterDate filterDate) {

        FilterDate dbFilterDate = filterDateService.loadByName(filterDate.getName());

        // If there is active saved filter date range with same name, and this is not updating then return error
        if (dbFilterDate != null)
            if ( (filterDate.getId() == null)
                    || (filterDate.getId() != dbFilterDate.getId())) {
                return RestResponse.failure("That name already exists.");
            }

        LOG.info("Saving filter date range " + filterDate.getName());
        filterDateService.saveOrUpdate(filterDate);
        return RestResponse.success(filterDate);

    }

    @RequestMapping(value = "dateRange/{filterId}/delete", method = RequestMethod.POST)
    public @ResponseBody Object deleteDateRange(@PathVariable int filterId) {
        FilterDate dbFilterDate = filterDateService.loadById(filterId);
        LOG.info("Deleting filter date range " + dbFilterDate.getName());
        filterDateService.markInactive(dbFilterDate);
        return RestResponse.success("Successfully deleted date range");
    }

}
