////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.FilterJsonBlobService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Controller
@RequestMapping("/reports/filter/")
public class JsonFilterBlobController {

    @Autowired
    private FilterJsonBlobService filterJsonBlobService;

    @RequestMapping(value = "save", method = RequestMethod.POST)
    public @ResponseBody RestResponse<List<FilterJsonBlob>> load(@ModelAttribute FilterJsonBlob filterJsonBlob) {
        filterJsonBlobService.saveOrUpdate(filterJsonBlob);
        return RestResponse.success(filterJsonBlobService.loadAllActive());
    }

}
