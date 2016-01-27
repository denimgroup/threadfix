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
package com.denimgroup.threadfix.sonarplugin;

import org.sonar.api.resources.AbstractLanguage;

/**
 *
 * Having this as a language allows sonar analysis for projects that aren't in the included set of profiles.
 *
 * Using it will require two analysis runs.
 *
 * Created by mcollins on 2/4/15
 */
public class ThreadFixLanguage extends AbstractLanguage {

    public static final String LANGUAGE_KEY = "threadfix";

    public ThreadFixLanguage() {
        super(LANGUAGE_KEY, "ThreadFix");
    }

    @Override
    public String[] getFileSuffixes() {
        return new String[0];
    }
}
