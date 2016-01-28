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
package com.denimgroup.threadfix.importer.update.impl;

import com.denimgroup.threadfix.annotations.MappingsUpdater;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.RemoteProviderTypeDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.RemoteProviderAuthenticationField;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.SelectOption;
import com.denimgroup.threadfix.importer.update.Updater;
import com.denimgroup.threadfix.importer.util.RegexUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Service;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.listOf;
import static com.denimgroup.threadfix.importer.update.UpdaterConstants.REMOTE_PROVIDERS_FOLDER;

/**
 * Created by mac on 11/18/14.
 */
@Service
@MappingsUpdater
public class RemoteProviderUpdater extends SpringBeanAutowiringSupport implements Updater, Ordered {

    private static final SanitizedLogger LOG = new SanitizedLogger(RemoteProviderUpdater.class);

    @Autowired
    private RemoteProviderTypeDao remoteProviderTypeDao;
    @Autowired
    private ChannelTypeDao        channelTypeDao;
    @Autowired
    private ChannelVulnerabilityUpdater channelVulnerabilityUpdater;

    @Override
    public int getOrder() {
        return 500;
    }

    enum State {
        START, NAME, CREDENTIALS, CHANNEL_TYPE, AUTHENTICATION_FIELDS, OTHER_FIELDS
    }

    State currentState = State.START;

    private static final String TEXT_PATTERN = "(.*)\\(Tip:",
            TIP_PATTERN = "Tip:(.*)\\)";

    @Override
    public void doUpdate(String fileName, BufferedReader bufferedReader) throws IOException {
        LOG.debug("Performing mapping update for file " + fileName);

        assert remoteProviderTypeDao != null :
                "remoteProviderTypeService was null. This indicates an error in Spring autowiring.";

        String name = null, channelName = null;
        boolean usernamePassword = false;
        List<RemoteProviderAuthenticationField> fields = list();

        String line;
        while ((line = bufferedReader.readLine()) != null) {
            if (line.equals("type.name")) {
                currentState = State.NAME;
            } else if (line.equals("type.credentials")) {
                currentState = State.CREDENTIALS;
            } else if (line.equals("type.channelname")) {
                currentState = State.CHANNEL_TYPE;
            } else if (line.equals("type.authenticationfields")) {
                currentState = State.AUTHENTICATION_FIELDS;
            } else if (line.equals("type.otherfields")) {
                currentState = State.OTHER_FIELDS;
            } else if (currentState == State.NAME) {
                name = line.split(",")[0];
                channelVulnerabilityUpdater.updateChannelTypeInfo(line);
            } else if (currentState == State.CREDENTIALS) {
                usernamePassword = line.equalsIgnoreCase("usernamepassword");
            } else if (currentState == State.CHANNEL_TYPE) {
                channelName = line;
            } else if (currentState == State.AUTHENTICATION_FIELDS) {
                fields.add(parseAuthenticateField(line));
            } else if (currentState == State.OTHER_FIELDS) {
                fields.add(parseOtherField(line));
            }
        }

        if (name == null) {
            throw new IllegalStateException("Failed to get a remote provider name from " + fileName);
        }

        if (channelName == null) {
            throw new IllegalStateException("Failed to get a channel name from " + fileName);
        }

        RemoteProviderType databaseType = remoteProviderTypeDao.retrieveByName(name);

        ChannelType channelType = channelTypeDao.retrieveByName(channelName);

        assert channelType != null : "Got null channel type for string " + channelName;

        if (databaseType == null) {
            LOG.info("Creating new RemoteProviderType with name " + name);

            RemoteProviderType type = new RemoteProviderType();
            type.setName(name);
            type.setHasUserNamePassword(usernamePassword);
            type.setChannelType(channelType);
            updateAuthenticationFields(type, fields);

            remoteProviderTypeDao.saveOrUpdate(type);

        } else {
            LOG.debug(name + " was already present in the database.");

            databaseType.setHasUserNamePassword(usernamePassword);
            databaseType.setChannelType(channelType);
            updateAuthenticationFields(databaseType, fields);

            remoteProviderTypeDao.saveOrUpdate(databaseType);
        }
    }

    private void updateAuthenticationFields(
            RemoteProviderType type,
            List<RemoteProviderAuthenticationField> fields) {

        for (RemoteProviderAuthenticationField field : fields) {
            boolean found = false;

            if (type.getAuthenticationFields() == null) {
                type.setAuthenticationFields(listOf(RemoteProviderAuthenticationField.class));
            }

            for (RemoteProviderAuthenticationField oldField : type.getAuthenticationFields()) {
                if (oldField.getName().equals(field.getName())) {
                    oldField.setRequired(field.getRequired());
                    oldField.setSecret(field.isSecret());
                    oldField.setPlaceholder(field.getPlaceholder());
                    oldField.setSelectOptions(field.getSelectOptions());
                    oldField.setType(field.getType());
                    found = true;
                }
            }

            if (!found) {
                type.getAuthenticationFields().add(field);
                field.setRemoteProviderType(type);
            }
        }
    }

    private RemoteProviderAuthenticationField parseAuthenticateField(String line) {
        String[] split = line.split(",");
        if (split.length < 2) {
            throw new IllegalArgumentException("Line " + line + " didn't have at least two parts separated by a comma.");
        }

        RemoteProviderAuthenticationField field = new RemoteProviderAuthenticationField();

        if (split[1].equals("true")) {
            field.setSecret(true);
        } else if (split[1].equals("false")) {
            field.setSecret(false);
        } else {
            throw new IllegalArgumentException("The second section in " + line + " should be true or false.");
        }

        if (split.length > 2)
            if (split[2].equals("true")) {
                field.setRequired(true);
            } else if (split[2].equals("false")) {
                field.setRequired(false);
            } else {
                throw new IllegalArgumentException("The third section in " + line + " should be true or false.");
            }

        if (split.length > 3)
            field.setPlaceholder(split[3]);

        field.setName(split[0]);

        return field;
    }

    private RemoteProviderAuthenticationField parseOtherField(String line) {
        String[] split = line.split(",");
        if (split.length < 4) {
            throw new IllegalArgumentException("Line " + line + " didn't have at least 4 parts separated by a comma.");
        }

        RemoteProviderAuthenticationField field = new RemoteProviderAuthenticationField();
        field.setName(split[0]);
        field.setType(split[1]);
        field.setRequired(split[2].equals("true") ? true : false);

        for (int i=3; i<split.length; i++) {
            SelectOption option = new SelectOption();
            if (split[i] == null || split[1].isEmpty())
                continue;
            String text = RegexUtils.getRegexResult(split[i], TEXT_PATTERN);
            option.setValue(text == null ? split[i].trim() : text.trim());
            option.setTip(RegexUtils.getRegexResult(split[i], TIP_PATTERN));
            field.getSelectOptions().add(option);
        }

        return field;
    }

    @Override
    public String getFolder() {
        return REMOTE_PROVIDERS_FOLDER;
    }

}
