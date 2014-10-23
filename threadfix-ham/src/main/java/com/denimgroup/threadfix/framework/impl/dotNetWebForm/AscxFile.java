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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import java.io.File;

/**
 * Created by mac on 10/22/14.
 */
public class AscxFile {

    private static final SanitizedLogger LOG = new SanitizedLogger(AspxUniqueIdParser.class);
    private final File file;

    @Nonnull
    public static AscxFile parse(@Nonnull File file) {
        return new AscxFile(file);
    }

    final String name;

    AscxFile(File file) {
        assert file.exists() : "File didn't exist.";
        assert file.isFile() : "File was not a valid file.";
        LOG.debug("Got entry for partial file with name " + file.getName());
        this.file = file;
        name = file.getName();
    }

    // This method will proxy all events to the other tokenizer
    public void expandIn(EventBasedTokenizer tokenizer) {
        EventBasedTokenizerRunner.run(file, false, new ProxyTokenizer(tokenizer));
    }

    private static class ProxyTokenizer implements EventBasedTokenizer {
        @Nonnull
        private final EventBasedTokenizer tokenizer;

        private ProxyTokenizer(@Nonnull EventBasedTokenizer tokenizer) {
            this.tokenizer = tokenizer;
        }

        @Override
        public boolean shouldContinue() {
            return this.tokenizer.shouldContinue();
        }

        @Override
        public void processToken(int type, int lineNumber, String stringValue) {
            this.tokenizer.processToken(type, lineNumber, stringValue);
        }
    }
}
