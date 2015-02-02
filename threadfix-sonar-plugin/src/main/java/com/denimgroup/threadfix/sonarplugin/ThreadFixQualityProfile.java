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

import org.apache.commons.io.IOUtils;
import org.sonar.api.profiles.ProfileDefinition;
import org.sonar.api.profiles.RulesProfile;
import org.sonar.api.profiles.XMLProfileParser;
import org.sonar.api.utils.ValidationMessages;

import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Created by mcollins on 1/30/15.
 */
public class ThreadFixQualityProfile extends ProfileDefinition {
    private final XMLProfileParser parser;

    public ThreadFixQualityProfile(XMLProfileParser parser) {
        this.parser = parser;
    }

    @Override
    public RulesProfile createProfile(ValidationMessages validationMessages) {
        InputStream input = getClass().getResourceAsStream("/threadfix_profile.xml");
        InputStreamReader reader = new InputStreamReader(input);
        try {
            return parser.parse(reader, validationMessages);
        } finally {
            IOUtils.closeQuietly(reader);
        }
    }
}