package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.CustomCweText;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.CustomCweTextService;
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

    @Autowired
    private CustomCweTextService customCweTextService;

    @InitBinder
    public void initBinder(WebDataBinder dataBinder) {
        dataBinder.setValidator(new BeanValidator());
    }

    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder) {
        dataBinder.setAllowedFields("genericVulnerability.name", "customText");
    }

    @RequestMapping(method = RequestMethod.GET)
    public String index(Model model){

        model.addAttribute("customCweText", new CustomCweText());

        return INDEX_VIEW;
    }

    @RequestMapping(value = "/info", method = RequestMethod.GET)
    public @ResponseBody RestResponse<Map<String, Object>> info(){
        Map<String, Object> map = new HashMap<>();
        map.put("customCweTextList", customCweTextService.loadAll());
        map.put("genericVulnerabilities", genericVulnerabilityService.loadAll());
        return success(map);
    }

    @RequestMapping(value = "/new", method = RequestMethod.POST)
    public @ResponseBody RestResponse<CustomCweText> newSubmit(@Valid @ModelAttribute CustomCweText customCweText,
                                                               BindingResult result, Model model){

        if(!PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_CUSTOM_CWE_TEXT)){
            return failure("You do not have permission to do that.");
        }


        GenericVulnerability genericVulnerability = null;

        if(customCweText.getGenericVulnerability() != null){
            genericVulnerability = genericVulnerabilityService.loadByName(customCweText.getGenericVulnerability().getName());
            if(genericVulnerability == null){
                result.rejectValue("genericVulnerability", null, "This vulnerability was not found.");
            }
        }

        if(result.hasErrors()){
            return FormRestResponse.failure("Found some errors.", result);
        }

        CustomCweText existing = customCweTextService.loadByGenericVulnerability(genericVulnerability);

        if(existing != null){
            return FormRestResponse.failure("Custom text already exists for this CWE");
        }

        customCweText.setGenericVulnerability(genericVulnerability);

        customCweTextService.store(customCweText);

        return success(customCweText);
    }

    @RequestMapping(value = "/{customCweTextId}/edit", method = RequestMethod.POST)
    public @ResponseBody RestResponse<CustomCweText> editSubmit(@PathVariable("customCweTextId") Integer customCweTextId,
                                                                @Valid @ModelAttribute CustomCweText customCweText,
                                                                BindingResult result, Model model){

        if(!PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_CUSTOM_CWE_TEXT)){
            return failure("You do not have permission to do that.");
        }

        GenericVulnerability genericVulnerability = null;

        if(customCweText.getGenericVulnerability() != null){
            genericVulnerability = genericVulnerabilityService.loadByName(customCweText.getGenericVulnerability().getName());
            if(genericVulnerability == null){
                result.rejectValue("genericVulnerability", null, "This vulnerability was not found.");
            }
        }

        if(result.hasErrors()){
            return FormRestResponse.failure("Found some errors.", result);
        }

        CustomCweText existing = customCweTextService.loadByGenericVulnerability(genericVulnerability);

        if(existing != null && !existing.getId().equals(customCweTextId)){
            return FormRestResponse.failure("Custom text already exists for this CWE");
        }

        CustomCweText databaseCustomCweText = customCweTextService.loadById(customCweTextId);
        databaseCustomCweText.setGenericVulnerability(genericVulnerabilityService.loadByName(customCweText.getGenericVulnerability().getName()));
        databaseCustomCweText.setCustomText(customCweText.getCustomText());

        customCweTextService.store(databaseCustomCweText);

        return success(databaseCustomCweText);
    }

    @RequestMapping(value = "/{customCweTextId}/delete", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> delete(@PathVariable("customCweTextId") Integer customCweTextId){

        if(!PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_CUSTOM_CWE_TEXT)){
            return failure("You do not have permission to do that.");
        }

        CustomCweText customCweText = customCweTextService.loadById(customCweTextId);

        if(customCweText != null){
            customCweTextService.delete(customCweText);
        }

        return RestResponse.success("Custom text was successfully deleted.");
    }
}
