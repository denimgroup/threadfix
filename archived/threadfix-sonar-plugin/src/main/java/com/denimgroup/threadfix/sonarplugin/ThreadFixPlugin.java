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

import com.denimgroup.threadfix.sonarplugin.profiles.*;
import com.denimgroup.threadfix.sonarplugin.rules.ThreadFixCWERulesDefinition;
import com.denimgroup.threadfix.sonarplugin.sensor.ThreadFixSensor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.Property;
import org.sonar.api.SonarPlugin;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mcollins on 1/28/15.
 */
@Property(key="threadfix.profiles", name="ThreadFix Profiles")
public class ThreadFixPlugin extends SonarPlugin {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixPlugin.class);

    @Override
    public List getExtensions() {
        LOG.debug("Getting extensions");

        return list(
                // metrics, UI, sensor
                ThreadFixMetrics.class,
                ThreadFixWidget.class,
                ThreadFixSensor.class,
                ThreadFixCWERulesDefinition.class,

                // add custom language
                ThreadFixLanguage.class,

                // language profiles
                AbapProfile.class,
                CobolProfile.class,
                CppProfile.class,
                CProfile.class,
                CSharpProfile.class,
                CssProfile.class,
                FlexProfile.class,
                GroovyProfile.class,
                JavaProfile.class,
                JavaScriptProfile.class,
                ObjcProfile.class,
                PhpProfile.class,
                PliProfile.class,
                PLSQLProfile.class,
                PythonProfile.class,
                RpgProfile.class,
                VbNetProfile.class,
                VbProfile.class,
                WebProfile.class,
                XmlProfile.class,

                // default extra language
                ThreadFixProfile.class
        );
    }

}
