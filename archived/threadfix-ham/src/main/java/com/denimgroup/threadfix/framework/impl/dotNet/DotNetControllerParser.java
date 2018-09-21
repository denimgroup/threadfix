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
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;
import static com.denimgroup.threadfix.framework.impl.dotNet.DotNetKeywords.*;

/**
 * Created by mac on 6/11/14.
 */
public class DotNetControllerParser implements EventBasedTokenizer {

    final DotNetControllerMappings mappings;

    public static final SanitizedLogger LOG = new SanitizedLogger(DotNetControllerParser.class);

    public static final Set<String> DOT_NET_BUILTIN_CONTROLLERS = set(
            "ApiController", "Controller", "HubController", "HubControllerBase", "AsyncController", "BaseController"
    );

    @Nonnull
    public static DotNetControllerMappings parse(@Nonnull File file) {
        DotNetControllerParser parser = new DotNetControllerParser(file);
        EventBasedTokenizerRunner.run(file, parser);
        return parser.mappings;
    }

    DotNetControllerParser(File file) {
        LOG.debug("Parsing controller mappings for " + file.getAbsolutePath());
        mappings = new DotNetControllerMappings(file.getAbsolutePath());
    }

    public boolean hasValidControllerMappings() {
        return mappings.hasValidMappings();
    }

    @Override
    public boolean shouldContinue() {
        return shouldContinue;
    }

    enum State {
        START, PUBLIC, CLASS, TYPE_SIGNATURE, BODY, PUBLIC_IN_BODY, ACTION_RESULT, IN_ACTION_SIGNATURE, AFTER_BIND_INCLUDE, DEFAULT_VALUE, IN_ACTION_BODY
    }

    enum AttributeState {
        START, OPEN_BRACKET, STRING
    }

    State currentState      = State.START;
    AttributeState currentAttributeState = AttributeState.START;
    Set<String> currentAttributes = set();
    String lastAttribute;
    int   currentCurlyBrace = 0, currentParen = 0, classBraceLevel = 0,
            methodBraceLevel = 0, storedParen = 0, methodLineNumber = 0;
    boolean shouldContinue = true;
    String  lastString     = null, methodName = null, twoStringsAgo = null;
    Set<String> currentParameters = set();
    Set<ModelField> parametersWithTypes = set();

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {

        processMainThread(type, lineNumber, stringValue);
        processAttributes(type, stringValue);

    }

    private void processMainThread(int type, int lineNumber, String stringValue) {

        switch (type) {
            case '{':
                currentCurlyBrace += 1;
                break;
            case '}':
                currentCurlyBrace -= 1;
                break;
            case '(':
                currentParen += 1;
                break;
            case ')':
                currentParen -= 1;
                break;
        }

        switch (currentState) {
            case START:
                if (PUBLIC.equals(stringValue)) {
                    currentState = State.PUBLIC;
                }
                break;
            case PUBLIC:
                currentState = CLASS.equals(stringValue) ?
                        State.CLASS :
                        State.START;
                break;
            case CLASS:
                if (stringValue != null && stringValue.endsWith("Controller") &&
                        // Make sure we're not parsing internal ASP.NET MVC controller classes
                        !DOT_NET_BUILTIN_CONTROLLERS.contains(stringValue)) {
                    String controllerName = stringValue.substring(0, stringValue.indexOf("Controller"));
                    LOG.debug("Got Controller name " + controllerName);
                    mappings.setControllerName(controllerName);
                }

                currentState = State.TYPE_SIGNATURE;
                break;
            case TYPE_SIGNATURE:
                if (type == '{') {
                    currentState = State.BODY;
                    classBraceLevel = currentCurlyBrace - 1;
                }
                break;
            case BODY:
                if (classBraceLevel == currentCurlyBrace) {
                    shouldContinue = false;
                } else if (PUBLIC.equals(stringValue)) {
                    currentState = State.PUBLIC_IN_BODY;
                }
                break;
            case PUBLIC_IN_BODY:
                if (ACTION_RESULT.equals(stringValue) ||
                        HTTP_MESSAGE_RESPONSE.equals(stringValue) ||
                        VIEW_RESULT.equals(stringValue)) {
                    currentState = State.ACTION_RESULT;
                } else if (type == '(' || type == ';' || type == '{') {
                    currentState = State.BODY;
                }
                break;
            case ACTION_RESULT:
                if (stringValue != null) {
                    lastString = stringValue;
                } else if (type == '(') {
                    assert lastString != null;

                    methodName = lastString;
                    lastString = null;
                    methodLineNumber = lineNumber;
                    storedParen = currentParen - 1;
                    lastString = null;
                    currentState = State.IN_ACTION_SIGNATURE;
                }

                break;
            case IN_ACTION_SIGNATURE:
                if (stringValue != null) {
                    twoStringsAgo = lastString;
                    lastString = stringValue;
                } else if (type == ',' || type == ')' && lastString != null) {
                    parametersWithTypes.add(new ModelField(twoStringsAgo, lastString));
                    if (twoStringsAgo.equals("Include")) {
                        currentState = State.AFTER_BIND_INCLUDE;
                    }
                } else if (type == '=' && !"Include".equals(lastString)) {
                    currentState = State.DEFAULT_VALUE;
                }

                if (currentParen == storedParen) {
                    currentState = State.IN_ACTION_BODY;
                    methodBraceLevel = currentCurlyBrace;
                }
                break;
            case DEFAULT_VALUE:
                if (stringValue != null) {
                    currentState = State.IN_ACTION_SIGNATURE;
                }
                break;
            case AFTER_BIND_INCLUDE:
                if (type == ',') {
                    currentState = State.IN_ACTION_SIGNATURE;
                }

                if (type == ')' && currentParen == storedParen) {
                    currentState = State.IN_ACTION_BODY;
                    methodBraceLevel = currentCurlyBrace;
                }
                break;
            case IN_ACTION_BODY:
                if (currentCurlyBrace == methodBraceLevel) {
                    mappings.addAction(
                            methodName, currentAttributes, methodLineNumber,
                            lineNumber, currentParameters, parametersWithTypes);
                    currentAttributes = set();
                    currentParameters = set();
                    parametersWithTypes = set();
                    methodName = null;
                    currentState = State.BODY;
                }
                break;
        }

    }

    private void processAttributes(int type, String stringValue) {
        if (currentState == State.BODY) {
            switch (currentAttributeState) {
                case START:
                    if (type == '[') {
                        currentAttributeState = AttributeState.OPEN_BRACKET;
                    }
                    break;
                case OPEN_BRACKET:
                    if (stringValue != null) {
                        lastAttribute = stringValue;
                        currentAttributeState = AttributeState.STRING;
                    }
                    break;
                case STRING:
                    if (type == ']') {
                        LOG.debug("Adding " + lastAttribute);
                        currentAttributes.add(lastAttribute);
                    }
                    currentAttributeState = AttributeState.START;
                    break;
            }
        }
    }
}
