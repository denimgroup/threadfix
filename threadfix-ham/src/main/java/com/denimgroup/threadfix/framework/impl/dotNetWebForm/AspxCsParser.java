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
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.newMap;
import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mac on 9/4/14.
 */
public class AspxCsParser implements EventBasedTokenizer {

    public static final SanitizedLogger LOG = new SanitizedLogger(AspxParser.class);

    public final File file;
    public final String aspName;
    public final Map<Integer, Set<String>> lineNumberToParametersMap = newMap();

    @Nonnull
    public static AspxCsParser parse(@Nonnull File file) {
        AspxCsParser parser = new AspxCsParser(file);
        EventBasedTokenizerRunner.run(file, parser);
        return parser;
    }

    AspxCsParser(File file) {
        LOG.debug("Parsing mappings for " + file.getAbsolutePath());
        aspName = file.getName();
        this.file = file;
    }

    @Override
    public boolean shouldContinue() {
        return true;
    }


    enum MethodState {
        WAITING, ACTIVE, GOT_TEXT_VALUE
    }

    private ClassState  classState  = ClassState.START;
    private MethodState methodState = MethodState.WAITING;

    int currentCurlyLevel = 0, currentParenLevel = 0;

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {
        processBraceLevels(type);
        processMethodLevel(type, lineNumber, stringValue);
        processClassLevel(type, lineNumber, stringValue);
        processRequest(type, lineNumber, stringValue);
    }

    ////////////////////////////////////////////////////////////////////////////////////
    //                       Method-level Request[]-style parsing
    ////////////////////////////////////////////////////////////////////////////////////

    enum RequestState {
        START, REQUEST, OPEN_SQUARE
    }
    RequestState requestState = RequestState.START;

    private void processRequest(int type, int lineNumber, String stringValue) {
        switch (requestState) {
            case START:
                requestState = type == -3 && stringValue.equals("Request") ? RequestState.REQUEST : RequestState.START;
                break;
            case REQUEST:
                requestState = type == '[' ? RequestState.OPEN_SQUARE : RequestState.START;
                break;
            case OPEN_SQUARE:
                if (type == '"') {
                    lineNumberToParametersMap.put(lineNumber, set(stringValue));
                }
                requestState = RequestState.START;
                break;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////
    //                           Class-level parsing
    ////////////////////////////////////////////////////////////////////////////////////

    private void processBraceLevels(int type) {
        currentCurlyLevel +=
                type == '{' ?  1 :
                type == '}' ? -1 : 0;
        currentParenLevel +=
                type == '(' ?  1 :
                type == ')' ? -1 : 0;
    }

    enum ClassState {
        START, GOT_PAGE, OPEN_PAREN, IN_METHOD
    }

    String lastStringValue = null;
    int baseParenLevel = -1, baseCurlyLevel = -1;
    private void processClassLevel(int type, int lineNumber, String stringValue) {
        switch (classState) {
            case START:
                if ("System.Web.UI.Page".equals(stringValue)) {
                    classState = ClassState.GOT_PAGE;
                }
                break;
            case GOT_PAGE:
                if (stringValue != null) {
                    lastStringValue = stringValue;
                } else if ('(' == type) {
                    baseParenLevel = currentParenLevel - 1;
                    classState = ClassState.OPEN_PAREN;
                }
                break;
            case OPEN_PAREN:
                if (currentParenLevel == baseParenLevel && type == '{') {
                    classState = ClassState.IN_METHOD;
                    methodState = MethodState.ACTIVE;
                    baseCurlyLevel = currentCurlyLevel - 1;
                }
                break;
            case IN_METHOD:
                if (baseCurlyLevel == currentCurlyLevel) {
                    classState = ClassState.GOT_PAGE;
                    methodState = MethodState.WAITING;
                }
                break;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////
    //                           Method-level .Text-style parsing
    ////////////////////////////////////////////////////////////////////////////////////

    Set<String> currentParameters = set();
    int currentLineNumber = -1;
    int numSymbols = 0;

    boolean atStartOfStatement = false, capturedAtStartOfStatement = false;

    private void processMethodLevel(int type, int lineNumber, String stringValue) {
        switch (methodState) {
            case WAITING:
                // not in the method
                break;
            case ACTIVE:
                if (stringValue != null && passesVariableTest(stringValue)) {
                    currentParameters.add(extractVariable(stringValue));
                    methodState = MethodState.GOT_TEXT_VALUE;
                    numSymbols = 0;
                    currentLineNumber = lineNumber;
                    capturedAtStartOfStatement = atStartOfStatement;
                }
                break;
            case GOT_TEXT_VALUE:
                if (capturedAtStartOfStatement && type == '=') {
                    currentParameters.clear();
                    methodState = MethodState.ACTIVE;
                } else if (capturedAtStartOfStatement && numSymbols++ > 1) {
                    capturedAtStartOfStatement = false;
                }

                if (currentLineNumber != lineNumber) {
                    lineNumberToParametersMap.put(currentLineNumber, currentParameters);
                    currentLineNumber = -1;
                    currentParameters = set();
                    methodState = MethodState.ACTIVE;
                    processMethodLevel(type, lineNumber, stringValue);
                } else if (stringValue != null && passesVariableTest(stringValue)) {
                    currentParameters.add(extractVariable(stringValue));
                }
                break;
        }

        atStartOfStatement = type == ';' ||
                type == '{' ||
                type == '}' ||
                type == ')' ||
                (type == -3 && "else".equals(stringValue)); // ) is to catch braceless ifs
    }

    private boolean passesVariableTest(String token) {
        return (token.contains(".Text") && !token.contains("System.Text")) || token.contains(".Value");
    }

    private String extractVariable(String token) {
        assert passesVariableTest(token) : "Didn't pass variable test";

        if (token.contains(".Text")) {
            return token.substring(0, token.indexOf(".Text"));
        } else if (token.contains(".Value")) {
            return token.substring(0, token.indexOf(".Value"));
        } else {
            assert false : "We shouldn't have gotten here";
            return null;
        }
    }

    @Override
    public String toString() {
        return "AspxParser{" +
                aspName + ": " + lineNumberToParametersMap +
                '}';
    }
}
