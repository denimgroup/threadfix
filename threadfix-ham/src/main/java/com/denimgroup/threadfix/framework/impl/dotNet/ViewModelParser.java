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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.framework.impl.dotNet.DotNetKeywords.CLASS;
import static com.denimgroup.threadfix.framework.impl.dotNet.DotNetKeywords.NAMESPACE;

/**
 * Created by mac on 8/27/14.
 */
public class ViewModelParser implements EventBasedTokenizer {

    Map<String, Set<ModelField>> map           = map();
    Map<String, String>          superClassMap = map();

    public static final SanitizedLogger LOG = new SanitizedLogger(ViewModelParser.class);

    @Nonnull
    public static ViewModelParser parse(@Nonnull File file) {
        ViewModelParser parser = new ViewModelParser();
        EventBasedTokenizerRunner.run(file, parser);
        return parser;
    }

    @Override
    public boolean shouldContinue() {
        return true; // TODO determine end condition
    }

    enum Phase {
        START, NAMESPACE, CLASS
    }

    enum ClassState {
        GET_NAME, WAIT_FOR_BRACE, IN_CLASS, ATTRIBUTE, PAREN, METHOD,
        IN_PROPERTY, PROPERTY_GET, PROPERTY_SET, EXTENDS, PROPERTY_DONE
    }

    Phase      currentPhase = Phase.START;
    ClassState classState   = ClassState.GET_NAME;

    int braceLevel          = 0;
    int namespaceBraceLevel = -1;

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {

        if (type == '{') {
            braceLevel++;
        } else if (type == '}') {
            braceLevel--;
        }

        LOG.debug("type = " + type + ", line = " + lineNumber + ", stringValue = " + stringValue);
        LOG.debug("phase = " + currentPhase + ", state = " + classState);
        LOG.debug("braceLevel is " + braceLevel);

        switch (currentPhase) {
            case START:
                if (NAMESPACE.equals(stringValue)) {
                    currentPhase = Phase.NAMESPACE;
                }
                break;
            case NAMESPACE:
                if (CLASS.equals(stringValue)) {
                    currentPhase = Phase.CLASS;
                    namespaceBraceLevel = braceLevel;
                }
                break;
            case CLASS:
                processClassEvent(type, stringValue);
                break;
        }

        LOG.debug("");
    }

    String currentModelName;
    String previousString = null, twoStringsAgo = null, threeStringsAgo = null;

    int classBraceLevel  = -1;
    int methodBraceLevel = -1;
    boolean isMultiValueType = false, isFirstTypeAfterBracket = true;

    private void processClassEvent(int type, String stringValue) {
        switch (classState) {
            case GET_NAME:
                if (stringValue != null) {
                    currentModelName = stringValue;
                    classState = ClassState.WAIT_FOR_BRACE;
                }
                break;
            case WAIT_FOR_BRACE:
                if (type == '{') {
                    classState = ClassState.IN_CLASS;
                } else if (":".equals(stringValue)) {
                    classState = ClassState.EXTENDS;
                }
                break;
            case EXTENDS:
                if (type == '{') {
                    classState = ClassState.IN_CLASS;
                } else if (stringValue != null) {
                    superClassMap.put(currentModelName, stringValue);
                }
                break;
            case IN_CLASS:
                if (stringValue != null) {
                    threeStringsAgo = twoStringsAgo;
                    twoStringsAgo = previousString;
                    previousString = stringValue;
                } else if ('(' == type) {
                    classState = ClassState.PAREN;
                    methodBraceLevel = braceLevel;
                } else if ('{' == type) {
                    classState = ClassState.IN_PROPERTY;
                    LOG.debug("Setting classBraceLevel to " + (braceLevel - 1));
                    classBraceLevel = braceLevel - 1;
                } else if ('[' == type) {
                    classState = ClassState.ATTRIBUTE;
                }
                break;
            case ATTRIBUTE:
                if (']' == type) {
                    classState = ClassState.IN_CLASS;
                    isMultiValueType = isFirstTypeAfterBracket;
                } else {
                    isFirstTypeAfterBracket = false;
                }
                break;
            case PAREN:
                if ('{' == type) {
                    classState = ClassState.METHOD;
                }
                break;
            case METHOD:
                if (methodBraceLevel == braceLevel) {
                    classState = ClassState.IN_CLASS;
                }
                break;
            case IN_PROPERTY:
                if (classBraceLevel == braceLevel) {

                    String parameter = previousString;

                    if ((threeStringsAgo != null &&
                            (threeStringsAgo.contains("Collection") ||
                             threeStringsAgo.contains("Enumerable") ||
                             threeStringsAgo.contains("List") ||
                             threeStringsAgo.contains("Set")))
                            || isMultiValueType
                            ) {
                        parameter = parameter + "[0]";
                    }

                    add(currentModelName, twoStringsAgo, parameter);
                    classState = ClassState.IN_CLASS;
                    isMultiValueType = false;
                    isFirstTypeAfterBracket = true;
                }
                break;
        }

        if (classState == ClassState.IN_CLASS && braceLevel == namespaceBraceLevel) {
            currentPhase = Phase.NAMESPACE;
            classState = ClassState.GET_NAME;
        }
    }

    private void add(String currentModelName, String propertyType, String propertyName) {
        if (!map.containsKey(currentModelName)) {
            map.put(currentModelName, new HashSet<ModelField>());
        }

        map.get(currentModelName).add(new ModelField(propertyType, propertyName));
    }

    @Override
    public String toString() {
        return map.toString();
    }

}
