////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.dao.WafTypeDao;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.importer.update.Updater;
import com.denimgroup.threadfix.importer.update.UpdaterConstants;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Service;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import java.io.BufferedReader;
import java.io.IOException;

import static com.denimgroup.threadfix.CollectionUtils.listOf;

/**
 * Created by mac on 9/12/14.
 */
@Service
@MappingsUpdater
public class WafsUpdater extends SpringBeanAutowiringSupport implements Updater, Ordered {

    private static final SanitizedLogger LOG = new SanitizedLogger(WafsUpdater.class);

    @Autowired
    WafTypeDao wafTypeDao;
    @Autowired
    WafRuleDirectiveDao wafRuleDirectiveDao;

    @Override
    public int getOrder() {
        return 300;
    }

    enum State {
        START, NAME, DIRECTIVES
    }

    @Override
    public void doUpdate(String fileName, BufferedReader bufferedReader) throws IOException {
        LOG.info("Updating mapping for file " + fileName);

        State state = State.START;

        WafType type = null;

        String line = bufferedReader.readLine();
        while (line != null) {

            String trimmedLine = line.trim();
            if ("type.name".equals(trimmedLine)) {
                state = State.NAME;
            } else if ("type.directives".equals(trimmedLine)) {
                state = State.DIRECTIVES;
            } else {
                switch (state) {
                    case START:
                        throw new IllegalStateException("There should be no content before type.name or type.directives");
                    case NAME:
                        type = processName(trimmedLine);
                        break;
                    case DIRECTIVES:
                        if (type == null) {
                            throw new IllegalStateException("The type.name section must come before the type.directives section.");
                        }
                        processRule(type, trimmedLine);
                        break;
                }
            }

            line = bufferedReader.readLine();
        }

        if (type != null) {
            wafTypeDao.saveOrUpdate(type);
        }
    }

    private void processRule(WafType type, String trimmedLine) {
        WafRuleDirective wafRuleDirective = wafRuleDirectiveDao.retrieveByWafTypeIdAndDirective(type, trimmedLine);

        if (wafRuleDirective == null) {
            WafRuleDirective directive = new WafRuleDirective();
            directive.setWafType(type);
            directive.setDirective(trimmedLine);
            type.getWafRuleDirectives().add(directive);
            wafRuleDirectiveDao.saveOrUpdate(directive);
        }
    }

    private WafType processName(String trimmedLine) {
        WafType maybeType = wafTypeDao.retrieveByName(trimmedLine);

        if (maybeType == null) {
            WafType type = new WafType();
            type.setName(trimmedLine);
            type.setInitialId(100000);
            type.setWafRuleDirectives(listOf(WafRuleDirective.class));
            wafTypeDao.saveOrUpdate(type);
            return type;
        } else {
            return maybeType;
        }
    }

    @Override
    public String getFolder() {
        return UpdaterConstants.WAFS_FOLDER;
    }
}
