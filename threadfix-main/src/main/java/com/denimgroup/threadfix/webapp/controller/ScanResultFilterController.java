package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScanResultFilter;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.ScanResultFilterService;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@Controller
@RequestMapping("/customize/scannerSeverities")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_SCAN_RESULT_FILTERS')")
public class ScanResultFilterController {

    private static final String INDEX_VIEW = "customize/scannerSeverities";

    private final SanitizedLogger log = new SanitizedLogger(ScanResultFilterController.class);

    @Autowired
    private ScanResultFilterService scanResultFilterService;

    @Autowired
    private GenericSeverityService genericSeverityService;

    @Autowired
    private ChannelTypeService channelTypeService;

    @InitBinder
    public void initBinder(WebDataBinder dataBinder) {
        dataBinder.setValidator(new BeanValidator());
    }

    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder) {
        dataBinder.setAllowedFields("genericSeverity.id", "channelType.id");
    }

    @RequestMapping(method = RequestMethod.GET)
    public String index(Model model){
        model.addAttribute("scanResultFilterList", scanResultFilterService.loadAll());
        model.addAttribute("scanResultFilter", new ScanResultFilter());

        if (EnterpriseTest.isEnterprise()) {
            return "customize/scannerSeverity/enterprise";
        } else {
            return "customize/scannerSeverity/community";
        }
    }

    @RequestMapping(value = "/info", method = RequestMethod.GET)
    public @ResponseBody RestResponse<Map<String, Object>> info(){
        Map<String, Object> map = new HashMap<>();
        map.put("scanResultFilters", scanResultFilterService.loadAll());
        map.put("channelTypes", channelTypeService.loadAll());
        map.put("severities", genericSeverityService.loadAll());
        return success(map);
    }


    @RequestMapping(value = "/new", method = RequestMethod.POST)
    public @ResponseBody RestResponse<ScanResultFilter> newSubmit(HttpServletRequest request,
                                                                  @Valid @ModelAttribute ScanResultFilter scanResultFilter,
                                                                  BindingResult result, Model model){

        if (!PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_SCAN_RESULT_FILTERS)) {
            return RestResponse.failure("You do not have permission to do that.");
        }

        if (result.hasErrors()) {
            return FormRestResponse.failure("Found some errors.", result);
        }

        ScanResultFilter existingScanResultFilter = scanResultFilterService.loadByChannelTypeAndSeverity(
                scanResultFilter.getChannelType(), scanResultFilter.getGenericSeverity());

        if(existingScanResultFilter != null){
            return failure("Filter already exists for this scanner type and severity.");
        }

        scanResultFilter.setGenericSeverity(genericSeverityService.loadById(scanResultFilter.getGenericSeverity().getId()));
        scanResultFilter.setChannelType(channelTypeService.loadChannel(scanResultFilter.getChannelType().getId()));
        scanResultFilterService.storeAndApplyFilter(scanResultFilter);

        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        log.info(String.format("%s has successfully created a Scan Result Filter for scannerType: %s and severity: %s",
                username, scanResultFilter.getChannelType().getName(), scanResultFilter.getGenericSeverity().getName()));

        return success(scanResultFilter);
    }

    @RequestMapping(value = "/{scanResultFilterId}/edit", method = RequestMethod.POST)
    public @ResponseBody RestResponse<ScanResultFilter> editSubmit(@PathVariable("scanResultFilterId") int scanResultFilterId,
                                                                   @Valid @ModelAttribute ScanResultFilter scanResultFilter,
                                                                   BindingResult result, Model model){

        if (!PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_SCAN_RESULT_FILTERS)) {
            return RestResponse.failure("You do not have permission to do that.");
        }

        if (result.hasErrors()) {
            return FormRestResponse.failure("Found some errors.", result);
        }

        ScanResultFilter existingScanResultFilter = scanResultFilterService.loadByChannelTypeAndSeverity(
                scanResultFilter.getChannelType(), scanResultFilter.getGenericSeverity());

        if(existingScanResultFilter != null && !existingScanResultFilter.getId().equals(scanResultFilterId)){
            return failure("Filter already exists for this scanner type and severity.");
        }

        ScanResultFilter databaseScanResultFilter = scanResultFilterService.loadById(scanResultFilterId);
        GenericSeverity previousGenericSeverity = databaseScanResultFilter.getGenericSeverity();
        ChannelType previousChannelType = databaseScanResultFilter.getChannelType();
        databaseScanResultFilter.setGenericSeverity(genericSeverityService.loadById(scanResultFilter.getGenericSeverity().getId()));
        databaseScanResultFilter.setChannelType(channelTypeService.loadChannel(scanResultFilter.getChannelType().getId()));

        scanResultFilterService.storeAndApplyFilter(databaseScanResultFilter, previousGenericSeverity, previousChannelType);

        return success(databaseScanResultFilter);
    }

    @RequestMapping(value = "/{scanResultFilterId}/delete", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> delete(@PathVariable("scanResultFilterId") int scanResultFilterId){
        if (!PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_SCAN_RESULT_FILTERS)) {
            return RestResponse.failure("You do not have permission to do that.");
        }

        ScanResultFilter scanResultFilter = scanResultFilterService.loadById(scanResultFilterId);

        if(scanResultFilter != null){
            scanResultFilterService.delete(scanResultFilter);
        }

        return RestResponse.success("Scan result filter was successfully deleted.");
    }
}
