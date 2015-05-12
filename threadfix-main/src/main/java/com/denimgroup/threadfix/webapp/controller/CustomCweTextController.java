package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.GenericVulnerabilityService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@Controller
@RequestMapping("/configuration/customCweText")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_CUSTOM_CWE_TEXT')")
public class CustomCweTextController {
    
    private static final String INDEX_VIEW = "config/customCweText/index";
    
    private final SanitizedLogger log = new SanitizedLogger(CustomCweTextController.class);

    @Autowired
    private GenericVulnerabilityService genericVulnerabilityService;

    @InitBinder
    public void initBinder(WebDataBinder dataBinder) {
        dataBinder.setValidator(new BeanValidator());
    }

    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder) {
        dataBinder.setAllowedFields("name", "customText");
    }

    @RequestMapping(method = RequestMethod.GET)
    public String index(Model model){
        model.addAttribute("genericVulnerability", new GenericVulnerability());

        return INDEX_VIEW;
    }

    @RequestMapping(value = "/info", method = RequestMethod.GET)
    public @ResponseBody RestResponse<Map<String, Object>> info(){
        Map<String, Object> map = new HashMap<>();
        map.put("genericVulnerabilities", genericVulnerabilityService.loadAll());
        map.put("genericVulnerabilitiesWithCustomText", genericVulnerabilityService.loadAllWithCustomText());
        return success(map);
    }

    @RequestMapping(value = "/submit", method = RequestMethod.POST)
    public @ResponseBody RestResponse<GenericVulnerability> submit(@Valid @ModelAttribute GenericVulnerability genericVulnerability,
                                                                   BindingResult result, Model model){

        if(!PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_CUSTOM_CWE_TEXT)){
            return failure("You do not have permission to do that.");
        }

        GenericVulnerability databaseGenericVulnerability = genericVulnerabilityService.loadByName(genericVulnerability.getName());

        if(databaseGenericVulnerability == null){
            result.rejectValue("name", null, "This vulnerability was not found.");
        }

        if(result.hasErrors()){
            return FormRestResponse.failure("Found some errors.", result);
        }

        if(databaseGenericVulnerability == null){
            databaseGenericVulnerability.setCustomText(genericVulnerability.getCustomText());

            genericVulnerabilityService.store(databaseGenericVulnerability);
        }

        return success(databaseGenericVulnerability);
    }
}
