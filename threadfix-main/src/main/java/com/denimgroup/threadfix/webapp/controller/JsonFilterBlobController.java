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

import com.denimgroup.threadfix.data.entities.FilterJsonBlob;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.AcceptanceCriteriaStatusService;
import com.denimgroup.threadfix.service.FilterJsonBlobService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/reports/filter/")
public class JsonFilterBlobController {

    private static final SanitizedLogger LOG = new SanitizedLogger(JsonFilterBlobController.class);

    @Autowired
    private FilterJsonBlobService filterJsonBlobService;
    @Autowired
    private AcceptanceCriteriaStatusService acceptanceCriteriaStatusService;

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

            if (dbBlob != null && dbBlob.getAcceptanceCriteria() != null) {
                filterJsonBlob.setAcceptanceCriteria(dbBlob.getAcceptanceCriteria());
            }

            filterJsonBlobService.saveOrUpdate(filterJsonBlob);

            if (filterJsonBlob.getAcceptanceCriteria() != null) {
                acceptanceCriteriaStatusService.runStatusCheck(filterJsonBlob.getAcceptanceCriteria());
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

}
