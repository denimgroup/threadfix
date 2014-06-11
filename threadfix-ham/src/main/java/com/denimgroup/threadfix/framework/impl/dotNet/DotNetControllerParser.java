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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;

import javax.annotation.Nonnull;
import java.io.File;

/**
 * Created by mac on 6/11/14.
 */
public class DotNetControllerParser implements EventBasedTokenizer, DotNetKeywords {

    DotNetControllerMappings mappings = new DotNetControllerMappings();

    @Nonnull
    public static DotNetControllerMappings parse(@Nonnull File file) {
        DotNetControllerParser parser = new DotNetControllerParser();
        EventBasedTokenizerRunner.run(file, parser);
        return parser.mappings;
    }

    @Override
    public boolean shouldContinue() {
        return shouldContinue; // TODO determine end conditions
    }

    enum State {
        START, PUBLIC, CLASS, BODY, IN_ACTION_SIGNATURE, IN_ACTION_BODY
    }

    State currentState = State.START;
    int currentCurlyBrace = 0, currentParen = 0, classBraceLevel = 0, methodBraceLevel = 0, storedParen = 0;
    boolean shouldContinue = true;
    String lastString = null;

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {

        System.out.print(type + " ");
        System.out.println(stringValue);
        System.out.println("state: " + currentState);
        System.out.println(currentCurlyBrace);
        System.out.println(currentParen);
        System.out.println(classBraceLevel);
        System.out.println(methodBraceLevel);
        System.out.println(storedParen);

        switch (type) {
            case '{': currentCurlyBrace += 1; break;
            case '}': currentCurlyBrace -= 1; break;
            case '(': currentParen += 1; break;
            case ')': currentParen -= 1; break;
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
                if (stringValue != null && stringValue.endsWith("Controller") && !stringValue.equals("Controller")) {
                    mappings.setControllerName(stringValue.substring(0, stringValue.indexOf("Controller")));
                } else if (type == '{') {
                    currentState = State.BODY;
                    classBraceLevel = currentCurlyBrace - 1;
                }
                break;
            case BODY:
                if (classBraceLevel == currentCurlyBrace) {
                    shouldContinue = false;
                } else if (stringValue != null) {
                    lastString = stringValue;
                } else if (type == '(') {
                    assert lastString != null;

                    storedParen = currentParen - 1;
                    mappings.addAction(lastString);
                    currentState = State.IN_ACTION_SIGNATURE;
                }

                break;
            case IN_ACTION_SIGNATURE: // TODO add parameter parsing
                if (currentParen == storedParen) {
                    currentState = State.IN_ACTION_BODY;
                    methodBraceLevel = currentCurlyBrace;
                }
                break;
            case IN_ACTION_BODY:
                if (currentCurlyBrace == methodBraceLevel) {
                    currentState = State.BODY;
                }
                break;
        }
    }
}
