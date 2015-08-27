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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.DefaultConfigurationDao;
import com.denimgroup.threadfix.data.entities.CSVExportField;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.Report;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.beanutils.BeanToPropertyValueTransformer;
import org.apache.commons.collections.CollectionUtils;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncryptionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static com.denimgroup.threadfix.CollectionUtils.list;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class DefaultConfigServiceImpl implements DefaultConfigService {
	
	protected final SanitizedLogger log = new SanitizedLogger(DefaultConfigServiceImpl.class);
	
	@Autowired
	private DefaultConfigurationDao defaultConfigurationDao;

    @Transactional(readOnly = false)
	@Override
	public DefaultConfiguration loadCurrentConfiguration() {
        DefaultConfiguration configuration = defaultConfigurationDao.loadCurrentConfiguration();

        assert configuration != null;

        return decrypt(configuration);
	}

	@Override
	public void saveConfiguration(DefaultConfiguration config) {
		defaultConfigurationDao.saveOrUpdate(encrypt(config));
	}

    private DefaultConfiguration encrypt(DefaultConfiguration config) {
        assert config != null;

        try {
            if (config.getProxyPassword() != null && !config.getProxyPassword().trim().equals("")) {

                if (!config.getProxyPassword().equals(DefaultConfiguration.MASKED_PASSWORD)) {
                    config.setProxyPasswordEncrypted(ESAPI.encryptor().encrypt(config.getProxyPassword()));
                }

            } else {
                config.setProxyPasswordEncrypted(null);
            }

            if (config.getProxyUsername() != null && !config.getProxyUsername().trim().equals("")) {
                config.setProxyUsernameEncrypted(ESAPI.encryptor().encrypt(config.getProxyUsername()));
            } else {
                config.setProxyUsernameEncrypted(null);
            }

            if (!config.getActiveDirectoryUsername().trim().isEmpty()) {
                config.setActiveDirectoryUsernameEncrypted(ESAPI.encryptor().encrypt(config.getActiveDirectoryUsername()));
            } else {
                config.setActiveDirectoryUsernameEncrypted(null);
            }

            if (!config.getActiveDirectoryCredentials().trim().isEmpty()) {
                if (!config.getActiveDirectoryCredentials().equals(DefaultConfiguration.MASKED_PASSWORD)) {
                    config.setActiveDirectoryCredentialsEncrypted(ESAPI.encryptor().encrypt(config.getActiveDirectoryCredentials()));
                }
                config.setActiveDirectoryCredentials(DefaultConfiguration.MASKED_PASSWORD);
            } else {
                config.setActiveDirectoryCredentialsEncrypted(null);
            }

        } catch (EncryptionException e) {
            log.error("Encountered encryption exception, ESAPI configuration is probably incorrect. " +
                    "Check that ESAPI.properties is on the classpath.", e);
            assert false;
        }

        return config;
    }

    private DefaultConfiguration decrypt(DefaultConfiguration config) {
        assert config != null;

        try {
            if (config.getProxyPasswordEncrypted() != null && !"".equals(config.getProxyPasswordEncrypted())) {
                config.setProxyPassword(ESAPI.encryptor().decrypt(config.getProxyPasswordEncrypted()));
            }

            if (config.getProxyUsernameEncrypted() != null && !"".equals(config.getProxyUsernameEncrypted())) {
                config.setProxyUsername(ESAPI.encryptor().decrypt(config.getProxyUsernameEncrypted()));
            }

            String usernameEncrypted = config.getActiveDirectoryUsernameEncrypted();
            if (usernameEncrypted != null && !"".equals(usernameEncrypted)) {
                config.setActiveDirectoryUsername(ESAPI.encryptor().decrypt(usernameEncrypted));
            }

            String passwordEncrypted = config.getActiveDirectoryCredentialsEncrypted();
            if (passwordEncrypted != null && !"".equals(passwordEncrypted)) {
                config.setActiveDirectoryCredentials(ESAPI.encryptor().decrypt(passwordEncrypted));
            }

        } catch (EncryptionException e) {
            log.error("Encountered encryption exception, ESAPI configuration is probably incorrect. " +
                    "Check that ESAPI.properties is on the classpath.", e);
        }

        return config;
    }

    @Override
    public boolean isReportCacheDirty() {
        return !loadCurrentConfiguration().getHasCachedData();
    }

    @Override
    public boolean reportDuplicateExists(List<Report> reports) {

        Set<Integer> set = new HashSet<>();

        for (Report report : reports) {
            if (!set.add(report.getId())) {
                return true;
            }
        }

        return false;
    }

    @Override

    public List<CSVExportField> getUnassignedExportFields(List<CSVExportField> exportFields) {

        List<CSVExportField> enumFields = list();
        List<CSVExportField> tempEnumFields = Arrays.asList(CSVExportField.values());

        List<String> exportFieldDisplayNames = getDisplayNamesFromExportFields(exportFields);

        if (exportFields.size() > 0) {
            for (CSVExportField enumField : tempEnumFields) {
                if (!exportFieldDisplayNames.contains(enumField.getDisplayName())) {
                    enumFields.add(enumField);
                }
            }
        } else {
            enumFields = tempEnumFields;
        }

        return enumFields;
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<String> getDisplayNamesFromExportFields(List<CSVExportField> exportFields) {

        return  (List<String>)CollectionUtils.collect(exportFields,
                new BeanToPropertyValueTransformer("displayName"));

    }
}
