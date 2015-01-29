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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.web.AbstractRubyTemplate;
import org.sonar.api.web.Description;
import org.sonar.api.web.RubyRailsWidget;
import org.sonar.api.web.UserRole;

/**
 * Created by mcollins on 1/28/15.
 */
@UserRole(UserRole.USER)
@Description("Shows ThreadFix statistics.")
public class ThreadFixWidget extends AbstractRubyTemplate implements RubyRailsWidget {

        private static final Logger LOG = LoggerFactory.getLogger(ThreadFixWidget.class);


        public String getId() {
                return "threadfix";
        }
        public String getTitle() {
                return "ThreadFix";
        }
        protected String getTemplatePath() {
                // uncomment next line for change reloading during development
                //return "c:/projects/xxxxx/src/main/resources/xxxxx/sonar/idemetadata/idemetadata_widget.html.erb";
                LOG.info("Getting fully qualified path to erb");

                return "/Users/mcollins/git/threadfix/threadfix-sonar-plugin/src/main/resources/test.html.erb";
//                return "/test.html.erb";
        }
}
