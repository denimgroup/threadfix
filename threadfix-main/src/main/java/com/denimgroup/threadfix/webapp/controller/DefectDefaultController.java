package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefaultDefectField;
import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.service.defects.VersionOneDefectTracker;
import com.denimgroup.threadfix.viewmodel.DynamicFormField;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.denimgroup.threadfix.webapp.viewmodels.DefectViewModel;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

@Controller
@RequestMapping("/default/{defaultProfileId}")
public class DefectDefaultController {

	private static final SanitizedLogger LOG = new SanitizedLogger(DefectDefaultController.class);

	private static final String ERROR_MSG = "error_msg";

	@Autowired
	private VulnerabilityService vulnerabilityService;
	@Autowired
	private DefaultDefectFieldService defaultDefectFieldService;
	@Autowired
	private DefaultDefectProfileService defaultDefectProfileService;
	@Autowired
	private DefectTrackerService defectTrackerService;
	@Autowired
	private ApplicationService applicationService;
	@Autowired
	private DefaultTagMappingService defaultTagMappingService;

	@RequestMapping(value = "retrieve/{vulnsIds}", method = RequestMethod.GET)
	public @ResponseBody RestResponse<Map<String, Object>> getDefectDefaults(
			@PathVariable("vulnsIds") String vulnsIdsStr, //initially used int[] directly, but "," couldn't be parsed in csrf urls, have to use String and parse to ints
			@PathVariable("defaultProfileId") int defaultProfileId) {

		DefaultDefectProfile defaultProfile = defaultDefectProfileService.loadDefaultProfile(defaultProfileId);
		List<Vulnerability> vulnerabilities = list();

		String[] vulnsIds = vulnsIdsStr.split("-");
		try {
			for (int i=0; i < vulnsIds.length; i++) {
				Vulnerability vuln = vulnerabilityService.loadVulnerability(Integer.parseInt(vulnsIds[i]));
				if (vuln !=null) vulnerabilities.add(vuln);
			}
		}
		catch (NumberFormatException e) {
			return RestResponse.failure("Bad vulns ids provided");
		}

		LOG.info("Getting field values based on defect profile template for " + vulnerabilities.size() + " vulnerabilities.");

		if (vulnerabilities.size()!=0){
			Map<String, Object> result = map("defaultValues", (Object) defaultDefectProfileService.getAllDefaultValuesForVulns(defaultProfile, vulnerabilities));
			return RestResponse.success(result);
		}
		else {
			return RestResponse.failure("Wrong vulns ids provided");
		}
	}

	@RequestMapping(value = "update", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> updateDefectDefaults(
			@PathVariable("defaultProfileId") int defaultProfileId,
			@ModelAttribute DefectViewModel defectViewModel) {

		LOG.info("Updating the defaults for the defect profile with ID " + defaultProfileId);
		String newDefaultsJson = defectViewModel.getFieldsMapStr();
		List<DefaultDefectField> newDefaultFields = defaultDefectFieldService.parseDefaultDefectsFields(newDefaultsJson);
		DefaultDefectProfile defaultProfile = defaultDefectProfileService.loadDefaultProfile(defaultProfileId);

		defaultDefectProfileService.updateDefaultFields(defaultProfile, newDefaultFields);
		return RestResponse.success("Updating the defaults for the defect tracker");
	}

	//Retrieve all the existing defaults tags and default fields for this profile
	@JsonView(Object.class)
	@RequestMapping(value = "update", method = RequestMethod.GET)
	public @ResponseBody RestResponse<Map<String, Object>> getDefectDefaultsConfig(
			@PathVariable("defaultProfileId") int defaultProfileId){

		Map<String, Object> map = map();
		DefaultDefectProfile defaultProfile = defaultDefectProfileService.loadDefaultProfile(defaultProfileId);
		map.put("defaultTags", defaultTagMappingService.getTagsWithValueMappingFields());
		map.put("defaultDefectFields", defaultProfile.getDefaultDefectFields());
		LOG.info("about to send map with defaultsconfig");
		return RestResponse.success(map);
	}

	//most of this function is a copy from defectSubmission in ApplicationController
	@RequestMapping("defectSubmissionForm")
	public @ResponseBody RestResponse<Map<String, Object>> getDefectSubmissionForm(
			@PathVariable("defaultProfileId") int defaultProfileId) {

		DefaultDefectProfile defaultProfile = defaultDefectProfileService.loadDefaultProfile(defaultProfileId);
		Application referenceApplication = defaultProfile.getReferenceApplication();

		Map<String, Object> returnMap = addMetadataForm(referenceApplication);

		if (returnMap.get(ERROR_MSG) != null) {
			return RestResponse.failure(returnMap.get(ERROR_MSG).toString());
		} else {
			return RestResponse.success(returnMap);
		}
	}

	//This function is essentially a copy of addDefectModelAttributes currently in ApplicationController
	private Map<String, Object> addMetadataForm(Application application) {

		if (application == null || !application.isActive()) {
			LOG.warn(ResourceNotFoundException.getLogMessage("Application", application.getId()));
			throw new ResourceNotFoundException();
		}

		if (application.getDefectTracker() == null ||
				application.getDefectTracker().getDefectTrackerType() == null) {
			return null;
		}

		applicationService.decryptCredentials(application);

		AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
		ProjectMetadata data = null;

		Map<String, Object> map = new HashMap<>();
		if (dt != null) {
			data = defectTrackerService.getProjectMetadata(dt);
			if (dt.getLastError() != null && !dt.getLastError().isEmpty()) {
				map.put(ERROR_MSG, dt.getLastError());
				return map;
			}

			// adding additional scanner info checkbox, checking for null dynamicformfields
			List<DynamicFormField> editableFields = data.getEditableFields();

			if (editableFields != null) {
				//addAdditionalScannerInfoField(editableFields);
				//not bothering with this checkbox for defaults as default system doesn't currently support booleans (ignores them)

				//remove Order field in Version One dynamic form
				if (dt.getClass().equals(VersionOneDefectTracker.class)) {
					DynamicFormField orderField = null;
					for (DynamicFormField field : editableFields) {
						if (field.getName().equals("Order")) {
							orderField = field;
						}
					}
					if (orderField != null) {
						editableFields.remove(orderField);
					}
				}
			}
		}
		map.put("defectTrackerName", application.getDefectTracker().getDefectTrackerType().getName());
		map.put("projectMetadata", data);
		return map;
	}
}