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
package com.denimgroup.threadfix.framework.impl.rails;

import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FileUtils;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.StreamTokenizer;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by sgerick on 4/23/2015.
 */
public class RailsModelParser implements EventBasedTokenizer {

    private static final SanitizedLogger LOG = new SanitizedLogger("RailsParser");

    private enum ModelState {
        INIT, CLASS, ATTR_ACCESSOR
    }

    private Map<String, List<String>> models = new HashMap<>();
    private String modelName = new String();
    private List<String> modelAttributes = list();

    private ModelState currentModelState = ModelState.INIT;

    public static Map parse(@Nonnull File rootFile) {
        if (!rootFile.exists() || !rootFile.isDirectory()) {
            LOG.error("Root file not found or is not directory. Exiting.");
            return null;
        }
        File modelDir = new File(rootFile,"app/models");
        if (!modelDir.exists() || !modelDir.isDirectory()) {
            LOG.error("{rootFile}/app/models/ not found or is not directory. Exiting.");
            return null;
        }
        String[] rubyExtension  = new String[] { "rb" };
        Collection<File> rubyFiles = (Collection<File>) FileUtils.listFiles(modelDir, rubyExtension, true);

        RailsModelParser parser = new RailsModelParser();
        for (File rubyFile : rubyFiles) {
            parser.modelName = "";
            parser.modelAttributes = new ArrayList<>();
            EventBasedTokenizerRunner.runRails(rubyFile, parser);
            if (!parser.modelName.isEmpty()) {
                parser.models.put(parser.modelName, parser.modelAttributes);
            }
        }

        return parser.models;
    }


    @Override
    public boolean shouldContinue() {
        return true;
    }

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {
        String charValue = null;
        if (type > 0)
            charValue = String.valueOf(Character.toChars(type));

//        System.err.println();
//        System.err.println("line="+lineNumber);
//        System.err.println("sTyp="+type);
//        System.err.println("sVal="+stringValue);
//        System.err.println("cVal="+charValue);

        switch (currentModelState) {
            case CLASS:
                processClass(type, stringValue, charValue);
                break;
            case ATTR_ACCESSOR:
                processAttrAccessible(type, stringValue, charValue);
                break;
        }

        if (stringValue != null) {
            switch (stringValue.toLowerCase()) {
                case "class":
                    currentModelState = ModelState.CLASS;
                    break;
                case "attr_accessible":
                    currentModelState = ModelState.ATTR_ACCESSOR;
                    break;
                case "attr_accessor":
                    currentModelState = ModelState.ATTR_ACCESSOR;
                    break;
            }
        }
    }

    private void processClass(int type, String stringValue, String charValue) {
        if (type == StreamTokenizer.TT_WORD && stringValue != null) {
            modelName = stringValue;
            modelName = stringValue.replaceAll("([a-z])([A-Z]+)","$1_$2").toLowerCase();
            currentModelState = ModelState.INIT;
        }
    }

    private void processAttrAccessible(int type, String stringValue, String charValue) {
        if (type == StreamTokenizer.TT_WORD && stringValue.startsWith(":")
                                            && stringValue.length() > 1) {
            stringValue = stringValue.substring(1);
            modelAttributes.add(stringValue);
            return;
        } else if (",".equals(charValue)) {
            return;
        } else {
            currentModelState = ModelState.INIT;
            return;
        }
    }

}
