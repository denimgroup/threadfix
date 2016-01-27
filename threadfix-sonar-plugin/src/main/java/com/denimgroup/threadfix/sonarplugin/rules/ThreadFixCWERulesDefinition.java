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
package com.denimgroup.threadfix.sonarplugin.rules;

import com.denimgroup.threadfix.sonarplugin.ThreadFixLanguage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.BatchExtension;
import org.sonar.api.resources.Language;
import org.sonar.api.resources.Languages;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonar.api.server.rule.RulesDefinitionXmlLoader;

import java.io.InputStream;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class ThreadFixCWERulesDefinition implements RulesDefinition, BatchExtension {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixCWERulesDefinition.class);

    public static final String REPOSITORY_KEY = "threadfix-rules";

    List<String> languages = list(
            ThreadFixLanguage.LANGUAGE_KEY, "pli", "abap", "py", "vbnet", "php", "vb", "cs", "rpg", "js",
            "cobol", "c", "cpp", "objc", "web", "xml", "flex", "plsql", "java", "css", "grvy"
    );

    public ThreadFixCWERulesDefinition(Languages languages) {
        if (languages != null) {
            LOG.info("Got injected languages, reading now.");
            this.languages.clear();
            for (Language language : languages.all()) {
                this.languages.add(language.getKey());
            }
        }
    }

    @Override
    public void define(Context context) {

        // make a repo for each defined language
        for (String language : languages) {
            LOG.info("Creating rules for key " + language);
            NewRepository repository = getRepositoryForLanguage(context, language);
            repository.done();
        }
    }

    private NewRepository getRepositoryForLanguage(Context context, String language) {
        NewRepository newRepository = context
                .createRepository(getKey(language), language)
                .setName("ThreadFix");
        loadRulesInto(newRepository);
        return newRepository;
    }

    public static String getKey(String language) {
        return REPOSITORY_KEY + "-" + language;
    }

    private void loadRulesInto(NewRepository repo) {
        InputStream resourceAsStream = getClass().getResourceAsStream("/rules.xml");
        if (resourceAsStream == null) {
            LOG.info("Resource was null.");
        } else {
            LOG.debug("Got rules.xml as a resource.");
            new RulesDefinitionXmlLoader().load(repo, resourceAsStream, "UTF-8");
            int size = repo.rules().size();
            LOG.debug("Got " + size + " new rules.");
        }
    }
}