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

package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.service.defects.*;
import com.denimgroup.threadfix.viewmodels.DynamicFormField;
import com.denimgroup.threadfix.viewmodels.ProjectMetadata;
import com.denimgroup.threadfix.viewmodels.DefectViewModel;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

/**
 * @author zabdisubhan
 */

@RestController
@RequestMapping("/rest/defects/{appId}")
public class DefectSubmissionRestController extends TFRestController {

    @Autowired
    private DefectService defectService;
    @Autowired
    private DefectTrackerService defectTrackerService;
    @Autowired
    private VulnerabilityService vulnerabilityService;
    @Autowired
    private ApplicationService applicationService;

    @RequestMapping(headers="Accept=application/json", value="/defectSubmission ", method= RequestMethod.POST)
    @JsonView(AllViews.RestViewScan2_1.class)
    public Object submitDefect(HttpServletRequest request,
                               @PathVariable("appId") int appId) throws IOException {

        log.info("Received REST request for defect submission.");

        Application application = applicationService.loadApplication(appId);
        if (application == null || !application.isActive()) {
            return failure("Application with ID " + appId + " was requested, but not found.");
        }

        if (application.getDefectTracker() == null ||
                application.getDefectTracker().getDefectTrackerType() == null) {
            return failure("No defect tracker attached to chosen application.");
        }

        DefectViewModel defectViewModel = new DefectViewModel();
        AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
        Map<String,String[]> params = request.getParameterMap();
        List<Integer> vulnerabilityIds = list();
        String[] vulnIds = params.get("vulnerabilityIds");

        if (vulnIds == null || vulnIds.length == 0) {
            return failure("You must submit at least one vulnerability.");
        }

        try {
            for (String vulnId : vulnIds) {
                vulnerabilityIds.add(Integer.parseInt(vulnId));
            }
        } catch (NumberFormatException e) {
            return failure("Vulnerability IDs formatted incorrectly.");
        }

        defectViewModel.setVulnerabilityIds(vulnerabilityIds);

        if (dt.getClass().equals(BugzillaDefectTracker.class)) {
            defectViewModel.setSelectedComponent(getFirstOrNull(params, "selectedComponent"));
            defectViewModel.setSummary(getFirstOrNull(params, "summary"));
            defectViewModel.setPriority(getFirstOrNull(params, "priority"));
            defectViewModel.setVersion(getFirstOrNull(params, "version"));
            defectViewModel.setSeverity(getFirstOrNull(params, "severity"));
            defectViewModel.setStatus(getFirstOrNull(params, "status"));
            defectViewModel.setAdditionalScannerInfo("true".equals(getFirstOrNull(params, "additionalScannerInfo")));

        } else {
            Map<String, Object> fieldsMap = map();
            for (Map.Entry<String, String[]> param : params.entrySet()) {
                if (!param.getKey().equals("vulnerabilityIds"))
                    fieldsMap.put(param.getKey(), param.getValue()[0]);
            }

            Gson gson = new Gson();
            defectViewModel.setFieldsMapStr(gson.toJson(fieldsMap));
        }

        Map fieldsMap = defectViewModel.getFieldsMap();
        if (fieldsMap == null) {
            fieldsMap = map();
        }
        Object asi = fieldsMap.get("AdditionalScannerInfo");

        if (asi != null) {
            if ((Boolean) asi){
                defectViewModel.setAdditionalScannerInfo(true);
            }
        } else {
            if (defectViewModel.getAdditionalScannerInfo() == null) {
                defectViewModel.setAdditionalScannerInfo(false);
            }
        }

        List<Vulnerability> vulnerabilities = vulnerabilityService.loadVulnerabilityList(defectViewModel.getVulnerabilityIds());
        Map<String,Object> map = defectService.createDefect(vulnerabilities, defectViewModel.getSummary(),
                defectViewModel.getPreamble(),
                defectViewModel.getSelectedComponent(),
                defectViewModel.getVersion(),
                defectViewModel.getSeverity(),
                defectViewModel.getPriority(),
                defectViewModel.getStatus(),
                defectViewModel.getFieldsMap(),
                defectViewModel.getAdditionalScannerInfo());

        Defect newDefect = null;

        if (map.get(DefectService.DEFECT) instanceof Defect)
            newDefect = (Defect)map.get(DefectService.DEFECT);

        if (newDefect != null) {
            return success("The Defect was submitted to the tracker.");
        } else {
            return failure(map.get(DefectService.ERROR) == null ?
                    "The Defect couldn't be submitted to the tracker." : map.get(DefectService.ERROR).toString());
        }
    }
    
    private String getFirstOrNull(Map<String, String[]> map, String field) {
        if (map == null) {
            return null;
        }

        String[] value = map.get(field);
        if (value == null) {
            return null;
        }
        
        if (value.length == 0) {
            return null;
        }
        
        return value[0];
    }

    @RequestMapping(headers="Accept=application/json", value="/defectTrackerFields", method= RequestMethod.GET)
    @JsonView(AllViews.RestViewScan2_1.class)
    public RestResponse<List<DynamicFormField>> getDefectTrackerFields(@PathVariable("appId") int appId) throws IOException {

        log.info("Received REST request for defect submission inputs.");

        Application application = applicationService.loadApplication(appId);
        if (application == null || !application.isActive()) {
            return failure("Application with ID " + appId + " was requested, but not found.");
        }

        if (application.getDefectTracker() == null ||
                application.getDefectTracker().getDefectTrackerType() == null) {
            return failure("No defect tracker attached to chosen application.");
        }

        applicationService.decryptCredentials(application);

        AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);

        if (dt == null) {
            return failure("Unable to find defect tracker implementation for application " + application.getId());
        }

        ProjectMetadata data = defectTrackerService.getProjectMetadata(dt);
        if (dt.getLastError() != null && !dt.getLastError().isEmpty()) {
            return failure(dt.getLastError());
        }

        List<DynamicFormField> editableFields = data.getEditableFields();

        if (editableFields != null) {
            addVulnerabilityIdsField(editableFields);
        }

        if (dt.getClass().equals(BugzillaDefectTracker.class)) {
            editableFields = list();
            addGenericDefectFields(editableFields, dt);
            data.setEditableFields(editableFields);
        }

        if (data.getEditableFields() == null || data.getEditableFields().isEmpty()) {
            return failure("Error retrieving fields from Defect Tracker.");
        }

        return success(data.getEditableFields());
    }

    private void addGenericDefectFields(@Nonnull List<DynamicFormField> formFields, AbstractDefectTracker dt) {
        DynamicFormField
                summary   = new DynamicFormField(),
                preamble  = new DynamicFormField(),
                component = new DynamicFormField(),
                version   = new DynamicFormField(),
                severity  = new DynamicFormField(),
                priority  = new DynamicFormField(),
                status    = new DynamicFormField();

        component.setName("selectedComponent");
        component.setRequired(false);
        component.setType("select");
        component.setActive(true);
        component.setSupportsMultivalue(true);

        priority.setRequired(false);
        priority.setName("priority");
        priority.setType("text");
        priority.setActive(true);

        status.setRequired(false);
        status.setName("status");
        status.setType("text");
        status.setActive(true);
        status.setSupportsMultivalue(false);

        if (dt.getClass().equals(VersionOneDefectTracker.class) ||
                dt.getClass().equals(BugzillaDefectTracker.class)) {
            version.setRequired(false);
            version.setName("version");
            version.setType("text");
            version.setActive(true);
            version.setSupportsMultivalue(false);

            severity.setRequired(false);
            severity.setName("severity");
            severity.setType("text");
            severity.setActive(true);
            severity.setSupportsMultivalue(false);

            formFields.add(version);
            formFields.add(severity);
        }

        summary.setRequired(false);
        summary.setName("summary");
        summary.setType("text");
        summary.setActive(true);
        summary.setSupportsMultivalue(false);

        preamble.setRequired(false);
        preamble.setName("preamble");
        preamble.setType("text");
        preamble.setActive(true);
        preamble.setSupportsMultivalue(false);

        formFields.add(component);
        formFields.add(priority);
        formFields.add(status);
        formFields.add(summary);
        formFields.add(preamble);
    }

    private void addVulnerabilityIdsField(@Nonnull List<DynamicFormField> formFields) {
        DynamicFormField vulnIdsField = new DynamicFormField();
        vulnIdsField.setName("vulnerabilityIds");
        vulnIdsField.setRequired(true);
        vulnIdsField.setType("list");
        vulnIdsField.setActive(true);
        vulnIdsField.setEditable(true);
        vulnIdsField.setSupportsMultivalue(false);

        formFields.add(vulnIdsField);
    }
    
}
