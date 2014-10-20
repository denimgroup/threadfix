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
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mac on 10/20/14.
 */
public class AspxUniqueIdParser implements EventBasedTokenizer {

    private static final SanitizedLogger LOG = new SanitizedLogger(AspxUniqueIdParser.class);
    private final AspxControlStack aspxControlStack;
    Set<String> parameters = set();

    int count = 1;

    @Nonnull
    public static AspxUniqueIdParser parse(@Nonnull File file) {
        AspxUniqueIdParser parser = new AspxUniqueIdParser(file);
        EventBasedTokenizerRunner.run(file, false, parser);
        return parser;
    }

    final String name;

    AspxUniqueIdParser(File file) {
        assert file.exists() : "File didn't exist.";
        assert file.isFile() : "File was not a valid file.";
        LOG.debug("Parsing controller mappings for " + file.getAbsolutePath());
        name = file.getName();

        aspxControlStack = new AspxControlStack();
    }

    @Override
    public boolean shouldContinue() {
        return true;
    }

    boolean endTag = false, print = false, needsId = false, gotIdAttribute = false;
    String lastName = null, lastId;

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {

        if (print) {
            if (type < 0) {
                System.out.println("type = " + type);
            } else {
                System.out.println("type = " + Character.valueOf((char) type));
            }
            System.out.println("line = " + lineNumber);
            System.out.println("stringValue = " + stringValue);
            System.out.println();
        }

        if (stringValue != null && stringValue.startsWith("asp")) {
            if (endTag) {
                System.out.println("Ending " + stringValue);
                removeTag(lastName, lastId);
            } else {
                System.out.println("Starting " + stringValue);
                lastName = stringValue;
                lastId = null;
                needsId = true;
            }
        }


        if (gotIdAttribute && stringValue != null) {
            lastId = stringValue;
            addTag(lastName, lastId);
            needsId = false;
            gotIdAttribute = false;
        }

        if ("asp:Content".equals(lastName)) {
            gotIdAttribute = gotIdAttribute || (needsId && stringValue != null && stringValue.equals("ContentPlaceHolderID"));
        } else {
            gotIdAttribute = gotIdAttribute || (needsId && stringValue != null && stringValue.contains("ID"));
        }

        if (type == '>') {
            if (needsId) {
                addTag(lastName, null); // TODO figure out better name generation scheme
            }

            if (endTag) { // self-closing tag
                // do that
                removeTag(lastName, lastId);
            }
        }

        endTag = type == '/';
    }

    private void addTag(String name, String id) {
        aspxControlStack.add(new AspxControl(name, id));
    }

    private void removeTag(String name, String id) {
        aspxControlStack.removeLast();

        if ("asp:BoundField".equals(name)) {
            addParamFor(name, id);
        }

        lastName = null;
        lastId = null;
    }

    private String autogenId() {
        return "ctl0" + count++;
    }

    private void addParamFor(String name, String id) {
        if (id == null) {
            id = autogenId();
        }

        parameters.add(aspxControlStack.generateNameFor(new AspxControl(name, id)));
        System.out.println("Parameters contains: " + parameters);
    }
}
