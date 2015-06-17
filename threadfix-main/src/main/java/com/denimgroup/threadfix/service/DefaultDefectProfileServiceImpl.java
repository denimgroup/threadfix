package com.denimgroup.threadfix.service;

import static com.denimgroup.threadfix.CollectionUtils.map;

import java.util.List;
import java.util.Map;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.DefaultDefectProfileDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefaultDefectField;
import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import org.springframework.validation.BindingResult;

@Service
public class DefaultDefectProfileServiceImpl implements DefaultDefectProfileService {

	@Autowired
	private DefaultDefectFieldService defaultDefectFieldService;
	@Autowired
	private SessionFactory sessionFactory;
	@Autowired
	private DefaultDefectProfileDao defaultDefectProfileDao;

	@Override
	public Map<String, Object> getAllDefaultValuesForVulns(DefaultDefectProfile defaultDefectProfile, List<Vulnerability> vulnerabilities) {
		List<DefaultDefectField> defaultDefectFields = defaultDefectProfile.getDefaultDefectFields();
		Map<String,Object> defaultValuesMap = map();
		for (DefaultDefectField defaultField : defaultDefectFields){
			String DefaultValue = defaultDefectFieldService.getDefaultValueForVulns(defaultField, vulnerabilities);
			if(DefaultValue != null){
				defaultValuesMap.put(defaultField.getFieldName(), DefaultValue);
			}
		}
		return defaultValuesMap;
	}

	@Override
	public void removeDefaultFields(DefaultDefectProfile defaultDefectProfile) { //this shouldn't be needed with jpa 2 if we used the remove orphans in the onetomany relationship
		List<DefaultDefectField> defaultDefectFields = defaultDefectProfile.getDefaultDefectFields();
		for (DefaultDefectField defaultDefectField : defaultDefectFields){
			sessionFactory.getCurrentSession().delete(defaultDefectField);
		}
	}

	//This is done by removing all existing and recreating with the new list
	@Override
	public void updateDefaultFields(DefaultDefectProfile defaultDefectProfile, List<DefaultDefectField> newDefaults) {
		removeDefaultFields(defaultDefectProfile);
		defaultDefectProfile.getDefaultDefectFields().clear();
		for (DefaultDefectField newDefault : newDefaults) {
			newDefault.setDefaultDefectProfile(defaultDefectProfile);
		}
		defaultDefectProfile.setDefaultDefectFields(newDefaults);
		defaultDefectProfileDao.saveOrUpdate(defaultDefectProfile);
	}

	@Override
	public DefaultDefectProfile loadDefaultProfile(Integer defaultProfileId) {
		return defaultDefectProfileDao.retrieveById(defaultProfileId);
	}

	@Override
	public void storeDefaultDefectProfile(DefaultDefectProfile defaultDefectProfile) {
		defaultDefectProfileDao.saveOrUpdate(defaultDefectProfile);
	}

	@Override
	public void deleteProfileById(Integer defaultProfileId) {
		DefaultDefectProfile defaultProfile = this.loadDefaultProfile(defaultProfileId);
		List<Application> applicationsWithMainProfile = defaultProfile.getApplicationsWithMainProfile();
		for (Application application : applicationsWithMainProfile){
			application.setMainDefaultDefectProfile(null);
		}
		defaultDefectProfileDao.deleteById(defaultProfileId);
	}

	@Override
	public DefaultDefectProfile loadAppDefectProfileByName(String name, Integer appId) {
		return defaultDefectProfileDao.retrieveDefectProfileByName(name, appId);
	}

	@Override
	public void validateName(DefaultDefectProfile defaultDefectProfile, BindingResult result) {
		DefaultDefectProfile dbProfile = loadAppDefectProfileByName(defaultDefectProfile.getName(), defaultDefectProfile.getReferenceApplication().getId());
		String msg = "The name is already taken for this application.";
		// If found that name of same application
		if (dbProfile != null) {
			// If default defect profile is new
			if (defaultDefectProfile.getId() == null)
				result.rejectValue("name", null, null, msg);
			else if (defaultDefectProfile.getId() != dbProfile.getId())
				result.rejectValue("name", null, null, msg);
		}
	}
}
