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
package com.denimgroup.threadfix.service.bootstrap;

import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.dao.WafTypeDao;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 8/13/15.
 */
@Component
public class WafBootstrapper {

    @Autowired
    WafTypeDao wafTypeDao;
    @Autowired
    WafRuleDirectiveDao wafRuleDirectiveDao;

    private static final SanitizedLogger LOG = new SanitizedLogger(WafBootstrapper.class);

    @Transactional
    public void bootstrap() {
        LOG.info("Checking and adding missing WAF Types.");

        Map<String, List<String>> typeToDirectivesMap = map(
                "Snort", list("alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop"),
                "mod_security", list("deny", "drop", "pass", "allow"),
                "BIG-IP ASM", list("transparent", "blocking"),
                "Imperva SecureSphere", list("-"),
                "DenyAll rWeb", list("deny", "warning"),
                "SteelApp Web App Firewall", list("deny")
        );

        ensureTypesExist(typeToDirectivesMap.keySet());

        for (Map.Entry<String, List<String>> entry : typeToDirectivesMap.entrySet()) {
            ensureDirectivesExist(entry.getKey(), entry.getValue());
        }
    }

    private void ensureTypesExist(Iterable<String> names) {
        for (String name : names) {

            WafType existingType = wafTypeDao.retrieveByName(name);

            if (existingType == null) {
                LOG.info("Adding WafType " + name);

                WafType newType = new WafType();

                newType.setName(name);

                wafTypeDao.saveOrUpdate(newType);
            } else {
                LOG.debug("Already had a WafType for " + name);
            }
        }
    }

    private void ensureDirectivesExist(String wafName, List<String> directives) {
        WafType type = wafTypeDao.retrieveByName(wafName);

        if (type == null) {
            throw new IllegalStateException("WafTypes are supposed to exist at this point.");
        }

        for (String directive : directives) {

            WafRuleDirective wafRuleDirective =
                    wafRuleDirectiveDao.retrieveByWafTypeIdAndDirective(type, directive);

            if (wafRuleDirective == null) {
                LOG.debug("Saving directive " + directive + " for waf type " + wafName);
                WafRuleDirective newDirective = new WafRuleDirective();

                newDirective.setDirective(directive);
                newDirective.setWafType(type);

                wafRuleDirectiveDao.saveOrUpdate(newDirective);
            } else {
                LOG.debug("Already had directive " + directive + " for waf type " + wafName);
            }

        }
    }


}
