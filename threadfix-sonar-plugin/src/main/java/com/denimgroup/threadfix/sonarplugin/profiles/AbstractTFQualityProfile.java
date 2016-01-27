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
package com.denimgroup.threadfix.sonarplugin.profiles;

import com.denimgroup.threadfix.sonarplugin.util.InputStreamLanguageDecorator;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.config.Settings;
import org.sonar.api.profiles.ProfileDefinition;
import org.sonar.api.profiles.RulesProfile;
import org.sonar.api.profiles.XMLProfileParser;
import org.sonar.api.resources.Languages;
import org.sonar.api.utils.ValidationMessages;

import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Created by mcollins on 1/30/15.
 */
public abstract class AbstractTFQualityProfile extends ProfileDefinition {

    private Settings settings;
    private Languages languages;
    private XMLProfileParser parser;
    private String languageKey;

    public AbstractTFQualityProfile(Settings settings, Languages languages, XMLProfileParser parser, String languageKey) {
        this.settings = settings;
        this.languages = languages;
        this.parser = parser;
        this.languageKey = languageKey;
    }

    private static final Logger LOG = LoggerFactory.getLogger(AbstractTFQualityProfile.class);

    @Override
    public RulesProfile createProfile(ValidationMessages validationMessages) {


        if (languages.get(languageKey) != null) {
            String string = settings.getString("threadfix.profiles");

            if (string == null) {
                LOG.info("No explicit profile configuration found, ThreadFix will submit profiles for all configured languages.");
                LOG.info("To change this behavior, set the property threadfix.profiles for this sonar installation.");
            } else if (csvContains(string, languageKey)) {
                LOG.info("Configuration was found and contained " + languageKey + ", continuing.");
            } else {
                LOG.info("Profiles were configured for ThreadFix and " + languageKey + " wasn't found in the list. Returning null.");
                return null;
            }

            InputStream input = AbstractTFQualityProfile.class.getResourceAsStream("/threadfix_profile.xml");
            InputStreamReader reader = new InputStreamReader(
                    new InputStreamLanguageDecorator(input, languageKey)
            );
            try {
                RulesProfile parse = parser.parse(reader, validationMessages);

                LOG.info("Got " + parse.getActiveRules().size() + " active rules for " + languageKey + ".");

                return parse;
            } finally {
                IOUtils.closeQuietly(reader);
            }
        } else {
            LOG.info("No language found for key " + languageKey + ", skipping.");
            return null;
        }
    }

    private boolean csvContains(String string, String languageKey) {

        if (string.contains(",")) {
            String[] split = string.split(",");

            for (String s : split) {
                if (languageKey.equals(s)) {
                    return true;
                }
            }
        } else if (string.equals(languageKey)) {
            return true;
        }

        return false;
    }
}