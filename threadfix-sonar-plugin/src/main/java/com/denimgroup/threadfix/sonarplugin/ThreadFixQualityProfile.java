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
package com.denimgroup.threadfix.sonarplugin;

import com.denimgroup.threadfix.sonarplugin.util.InputStreamLanguageDecorator;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.profiles.RulesProfile;
import org.sonar.api.profiles.XMLProfileParser;
import org.sonar.api.utils.ValidationMessages;

import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Created by mcollins on 1/30/15.
 */
public abstract class ThreadFixQualityProfile {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixQualityProfile.class);

    public static RulesProfile createProfile(XMLProfileParser parser,
                                             String languageKey,
                                             ValidationMessages validationMessages) {
        InputStream input = ThreadFixQualityProfile.class.getResourceAsStream("/threadfix_profile.xml");
        InputStreamReader reader = new InputStreamReader(
                new InputStreamLanguageDecorator(input, languageKey)
        );
        try {
            RulesProfile parse = parser.parse(reader, validationMessages);

            LOG.info("Got " + parse.getActiveRules().size() + " active rules for " + languageKey + ".");
            LOG.info("Got " + parse.getLanguage() + " for language.");

            return parse;
        } finally {
            IOUtils.closeQuietly(reader);
        }
    }
}