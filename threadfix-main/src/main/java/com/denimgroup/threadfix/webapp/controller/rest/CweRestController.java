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

package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.GenericVulnerabilityService;
import com.denimgroup.threadfix.util.Result;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

import static com.denimgroup.threadfix.remote.response.RestResponse.resultError;

/**
 * Created by skakani on 5/12/2015.
 */

@RestController
@RequestMapping("rest/cwe")
public class CweRestController extends TFRestController {

    @Autowired
    GenericVulnerabilityService genericVulnerabilityService;

    public static final String CWE_LOOK_UP_FAILED = "CWE look up failed. Check the ID";

    @JsonView(AllViews.RestCweView.class)
    @RequestMapping(value="/{cweId}/setCustomText", method= RequestMethod.POST, headers ="Accept=application/json")
    public Object setCustomText(HttpServletRequest request, @PathVariable("cweId") int cweId,@RequestParam("customText") String customText){

        LOG.info("Got REST request to set the custom text to CWE with id = " + cweId + ".");

        Result<String> keyCheck = checkKey(request, RestMethod.CWE_SET_CUSTOM_TEXT, -1, -1);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        GenericVulnerability genericVulnerability = genericVulnerabilityService.loadByDisplayId(cweId);

        if (genericVulnerability == null) {
            LOG.warn(CWE_LOOK_UP_FAILED);
            return RestResponse.failure(CWE_LOOK_UP_FAILED);
        } else {
            genericVulnerability.setCustomText(customText);
            genericVulnerabilityService.store(genericVulnerability);
        }

        Object response = RestResponse.success(genericVulnerability);

        // TODO evaluate the need for this
        // Removing redundant 'object.displayId' property from REST Response (We already have object.CweId)
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String serialized = objectMapper.writeValueAsString(response);
            JSONObject jsonObject = new JSONObject(serialized);
            jsonObject.getJSONObject("object").remove("displayId");
            return jsonObject.toString();

        } catch(JsonProcessingException e) {
            LOG.warn("Exception occurred during parsing/generating JSON");
            e.printStackTrace();
        } catch(JSONException e) {
            LOG.warn("JSON Exception occurred");
            e.printStackTrace();
        }
        return response;
    }

}
