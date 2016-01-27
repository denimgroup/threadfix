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

package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import javax.annotation.Nonnull;

import java.io.File;
import java.io.StreamTokenizer;

public class SpringJavaConfigurationChecker {

    public static boolean checkJavaFile(@Nonnull File file) {

        boolean result = false;

        // This won't work with, for example, a Spring Scala project w/ Scala configuration
        if (file.exists() && file.isFile() && file.getName().endsWith(".java")) {
            WebMvcChecker tokenizer = new WebMvcChecker();
            EventBasedTokenizerRunner.run(file, tokenizer);
            result = tokenizer.isWebMvc();
        }

        return result;
    }

    static class WebMvcChecker implements EventBasedTokenizer {

        boolean hasConfiguration = false, hasEnableWebMvc = false, hasExtends = false,
                isWebMvcConfigurationSupportSubclass = false,
                shouldContinue = true, arroba = false, beforeClass = true;

        public boolean isWebMvc() {
            return isWebMvcConfigurationSupportSubclass || (hasConfiguration && hasEnableWebMvc);
        }

        @Override
        public boolean shouldContinue() {
            return shouldContinue;
        }

        @Override
        public void processToken(int type, int lineNumber, String stringValue) {

            if (type == StreamTokenizer.TT_WORD) {
                if (stringValue.equals("Configuration")) {
                    hasConfiguration = arroba;
                } else if (stringValue.equals("EnableWebMvc")) {
                    hasEnableWebMvc = arroba;
                } else if (stringValue.equals("extends")) {
                    hasExtends = true;
                } else if (stringValue.equals("class")) {
                    beforeClass = false;
                } else if (stringValue.equals("WebMvcConfigurationSupport")) {
                    isWebMvcConfigurationSupportSubclass = hasExtends;

                } else {
                }
                arroba = false;
            } else if (type == ARROBA) {
                arroba = true;
            } else if (type == OPEN_CURLY) {
                shouldContinue = beforeClass;
            }
        }
    }

}
