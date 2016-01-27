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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.DefectDao;
import com.denimgroup.threadfix.data.dao.DefectTrackerDao;
import com.denimgroup.threadfix.data.dao.DefectTrackerTypeDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.data.interfaces.ProjectMetadataSource;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.service.defects.VersionOneDefectTracker;
import com.denimgroup.threadfix.viewmodels.DynamicFormField;
import com.denimgroup.threadfix.viewmodels.ProjectMetadata;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import javax.annotation.Nonnull;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Service
@Transactional(readOnly = false) // used to be true
public class DefectTrackerServiceImpl implements DefectTrackerService {

	private DefectTrackerDao defectTrackerDao = null;
	private DefectTrackerTypeDao defectTrackerTypeDao = null;
	private DefectDao defectDao = null;

	private final SanitizedLogger log = new SanitizedLogger("DefectTrackerService");

    private static final String ERROR_MSG = "error_msg";
	
	@Autowired
	public DefectTrackerServiceImpl(DefectTrackerDao defectTrackerDao,
			DefectTrackerTypeDao defectTrackerTypeDao, DefectDao defectDao) {
		this.defectTrackerDao = defectTrackerDao;
		this.defectTrackerTypeDao = defectTrackerTypeDao;
		this.defectDao = defectDao;
	}

	@Override
	public List<DefectTracker> loadAllDefectTrackers() {

        List<DefectTracker> decrypted = list();
        List<DefectTracker> encrypted = defectTrackerDao.retrieveAll();

        if (encrypted != null && !encrypted.isEmpty()) {
            for (DefectTracker defectTracker : encrypted) {
                decrypted.add(decryptCredentials(defectTracker));
            }
        }

		return decrypted;
	}

	@Override
	public DefectTracker loadDefectTracker(int defectId) {
		return decryptCredentials(defectTrackerDao.retrieveById(defectId));
	}

	@Override
	public DefectTracker loadDefectTracker(String name) {
		return decryptCredentials(defectTrackerDao.retrieveByName(name));
	}

	@Override
	@Transactional(readOnly = false)
	public void storeDefectTracker(DefectTracker defectTracker) {
		defectTrackerDao.saveOrUpdate(encryptCredentials(defectTracker));
	}

	@Override
	@Transactional(readOnly = false)
	public void deleteById(int defectTrackerId) {
		log.info("Deleting Defect tracker with ID " + defectTrackerId);
		
		defectDao.deleteByDefectTrackerId(defectTrackerId);
	
		DefectTracker tracker = defectTrackerDao.retrieveById(defectTrackerId);
		tracker.setActive(false);
		
		if (tracker.getApplications() != null && tracker.getApplications().size() > 0) {
			for (Application app : tracker.getApplications()) {
				log.info("Removing defect tracker and project credentials from " +
						"application with ID " + app.getId());
				app.setDefectTracker(null);
				app.setUserName(null);
				app.setPassword(null);
				app.setProjectId(null);
				app.setProjectName(null);
			}
		}
		
		tracker.setApplications(null);
		
		defectTrackerDao.saveOrUpdate(tracker);
	}

	@Override
	public List<DefectTrackerType> loadAllDefectTrackerTypes() {
        List<DefectTrackerType> types = defectTrackerTypeDao.retrieveAll();
        for (DefectTrackerType trackerType: types) {
            trackerType.setUrlPlaceholder(DefectTrackerType.DT_URL_PLACEHOLDER_MAP.get(trackerType.getName()));
        }
		return types;
	}

	@Override
	public DefectTrackerType loadDefectTrackerType(int defectId) {
		return defectTrackerTypeDao.retrieveById(defectId);
	}

    @Override
    public ProjectMetadata getProjectMetadata(ProjectMetadataSource tracker) {

        ProjectMetadata data = null;

        if (tracker != null) {

            data = tracker.getProjectMetadata();

            // adding additional scanner info checkbox, checking for null DynamicFormFields
            List<DynamicFormField> editableFields = data.getEditableFields();

            if (editableFields != null) {
                addAdditionalScannerInfoField(editableFields);

                //remove Order field in Version One dynamic form
                if (tracker.getClass().equals(VersionOneDefectTracker.class)) {
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

        return data;
    }

    private void addAdditionalScannerInfoField(@Nonnull List<DynamicFormField> formFields){
        DynamicFormField additionalScannerInfoField = new DynamicFormField();
        additionalScannerInfoField.setName("AdditionalScannerInfo");
        additionalScannerInfoField.setLabel("Include Scanner Detail");
        additionalScannerInfoField.setRequired(false);
        additionalScannerInfoField.setType("checkbox");
        additionalScannerInfoField.setActive(true);
        additionalScannerInfoField.setEditable(true);
        additionalScannerInfoField.setSupportsMultivalue(false);

        formFields.add(additionalScannerInfoField);
    }

	@Override
	public DefectTrackerType loadDefectTrackerType(String name) {
		return defectTrackerTypeDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeDefectTrackerType(DefectTrackerType defectTrackerType) {
		defectTrackerTypeDao.saveOrUpdate(defectTrackerType);
	}

	@Override
	public boolean checkUrl(DefectTracker defectTracker, BindingResult result) {
		if (defectTracker != null && defectTracker.getDefectTrackerType() != null &&
				defectTracker.getUrl() != null) {
			
			AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(
					defectTrackerTypeDao.retrieveById(defectTracker.getDefectTrackerType().getId()));
			
			if (tracker != null) {
				tracker.setUrl(defectTracker.getUrl());
				
				if (tracker.hasValidUrl()) {
					return true;
				} else if (tracker.getLastError() != null) {
					result.rejectValue("url", null, null, tracker.getLastError());
					return false;
				}
			}
		}
		
		return false;
	}

    @Override
    public boolean checkCredentials(DefectTracker defectTracker, BindingResult result) {

        if (defectTracker != null && defectTracker.getDefectTrackerType() != null && defectTracker.getUrl() != null
                && defectTracker.getDefaultUsername() != null && defectTracker.getDefaultPassword() != null) {

            AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(
                    defectTrackerTypeDao.retrieveById(defectTracker.getDefectTrackerType().getId()));

            if (tracker != null) {
                tracker.setUrl(defectTracker.getUrl());
                tracker.setUsername(defectTracker.getDefaultUsername());
                tracker.setPassword(defectTracker.getDefaultPassword());

                if (tracker.hasValidCredentials()) {
                    return true;
                } else if(tracker.getLastError() != null) {
                    result.rejectValue("defaultUsername", null, null, tracker.getLastError());
                }
            }
        }

        return false;
    }

    @Override
    public DefectTracker encryptCredentials(DefectTracker defectTracker) {

        try{
            if(defectTracker != null && defectTracker.getDefaultUsername() != null && !defectTracker.getDefaultUsername().isEmpty()
                    && defectTracker.getDefaultPassword() != null && !defectTracker.getDefaultPassword().isEmpty()){

                defectTracker.setEncryptedDefaultUsername(ESAPI.encryptor().encrypt(defectTracker.getDefaultUsername()));
                defectTracker.setEncryptedDefaultPassword(ESAPI.encryptor().encrypt(defectTracker.getDefaultPassword()));
            }
        } catch (EncryptionException e) {
            log.warn("Encountered an ESAPI encryption exception. Check your ESAPI configuration.", e);
        }

        return defectTracker;
    }

    @Override
    public DefectTracker decryptCredentials(DefectTracker defectTracker) {

        try{
            if(defectTracker != null && defectTracker.getEncryptedDefaultUsername() != null && !defectTracker.getEncryptedDefaultUsername().isEmpty()
                    && defectTracker.getEncryptedDefaultPassword() != null && !defectTracker.getEncryptedDefaultPassword().isEmpty()){

                defectTracker.setDefaultUsername(ESAPI.encryptor().decrypt(defectTracker.getEncryptedDefaultUsername()));
                defectTracker.setDefaultPassword(ESAPI.encryptor().decrypt(defectTracker.getEncryptedDefaultPassword()));
            }
        } catch (EncryptionException e) {
            log.warn("Encountered an ESAPI encryption exception. Check your ESAPI configuration.", e);
        }

        return defectTracker;
    }
}