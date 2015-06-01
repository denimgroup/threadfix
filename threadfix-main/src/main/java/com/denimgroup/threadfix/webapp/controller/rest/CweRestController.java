package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.GenericVulnerabilityService;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by skakani on 5/12/2015.
 */

@RestController
@RequestMapping("rest/cwe")
public class CweRestController extends TFRestController{

    @Autowired
    GenericVulnerabilityService genericVulnerabilityService;

    private static final String SET_CWE_CUSTOM_TEXT = "setCustomText";

    public static final String CWE_LOOK_UP_FAILED = "CWE look up failed. Check the ID";

    @JsonView(AllViews.RestCweView.class)
    @RequestMapping(value="/{cweId}/setCustomText", method= RequestMethod.POST, headers ="Accept=application/json")
    public Object setCustomText(HttpServletRequest request, @PathVariable("cweId") int cweId,@RequestParam("customText") String customText){

        log.info("Got REST request to set the custom text to CWE with id = " + cweId + ".");

        String result = checkKey(request,SET_CWE_CUSTOM_TEXT);
        if(!result.equals(API_KEY_SUCCESS)){
            return RestResponse.failure(result);
        }

        GenericVulnerability genericVulnerability = genericVulnerabilityService.loadByDisplayId(cweId);

        if(genericVulnerability == null){
            log.warn(CWE_LOOK_UP_FAILED);
            return RestResponse.failure(CWE_LOOK_UP_FAILED);
        }else{
            genericVulnerability.setCustomText(customText);
            genericVulnerabilityService.store(genericVulnerability);

        }
        Object response = RestResponse.success(genericVulnerability);

        //Removing redundant 'object.displayId' property from REST Response (We already have object.CweId)
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String serialized = objectMapper.writeValueAsString(response);
            JSONObject jsonObject = new JSONObject(serialized);
            jsonObject.getJSONObject("object").remove("displayId");
            return jsonObject.toString();

        }catch(JsonProcessingException e){
            log.warn("Exception occurred during parsing/generating JSON");
            e.printStackTrace();
        }catch(JSONException e){
            log.warn("JSON Exception occurred");
            e.printStackTrace();
        }
        return response;
    }

}
