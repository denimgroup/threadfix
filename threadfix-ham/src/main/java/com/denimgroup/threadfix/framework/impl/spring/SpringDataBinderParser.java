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

import javax.annotation.Nonnull;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * This class parses out DataBinder.setAllowedFields and DataBinder.setDisallowedFields calls.
 */
// TODO handle @InitBinder on objects (probably) (but not for now)
public class SpringDataBinderParser implements EventBasedTokenizer {

    boolean canHaveBinder = false, shouldContinue = true, isGlobal = false;
    public boolean hasWhitelist = false, hasBlacklist = false;
    String dataBinderName = null;

    int parenCount = 0, curlyCount = 0;

    @Nonnull // but you should check hasBlackList and hasWhitelist
    Set<String> parametersWhiteList = set(), parametersBlackList = set();

    private static final String
        INIT_BINDER = "InitBinder",
        DATA_BINDER = "DataBinder",
        CONTROLLER = "Controller",
        CONTROLLER_ADVICE = "ControllerAdvice",
        CLASS = "class",
        SET_ALLOWED_FIELDS = ".setAllowedFields",
        SET_DISALLOWED_FIELDS = ".setDisallowedFields";


    enum State {
        BEFORE_CLASS_BODY, ARROBA_BEFORE_CLASS, IN_CLASS_BODY, ARROBA,
        IN_PARAMS, GET_NEXT_STRING, METHOD_BODY, GET_WHITELIST, GET_BLACKLIST
    }

    State currentState = State.BEFORE_CLASS_BODY;

    @Override
    public boolean shouldContinue() {
        return shouldContinue;
    }

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {
        switch (currentState) {
            case BEFORE_CLASS_BODY:
                if (type == ARROBA) {
                    currentState = State.ARROBA_BEFORE_CLASS;
                } else if (CLASS.equals(stringValue)) {
                    if (canHaveBinder) {
                        currentState = State.IN_CLASS_BODY;
                    } else {
                        shouldContinue = false;
                    }
                }
                break;
            case ARROBA_BEFORE_CLASS:
                if (CONTROLLER.equals(stringValue) || CONTROLLER_ADVICE.equals(stringValue)) {
                    canHaveBinder = true;
                    isGlobal = CONTROLLER_ADVICE.equals(stringValue);
                }
                currentState = State.BEFORE_CLASS_BODY;
                break;
            case IN_CLASS_BODY:
                if (type == ARROBA) {
                    currentState = State.ARROBA;
                } // it's ok to loop here til EOF if we never get an arroba
                break;
            case ARROBA:
                if (INIT_BINDER.equals(stringValue)) {
                    currentState = State.IN_PARAMS;
                } else {
                    currentState = State.IN_CLASS_BODY;
                }
                break;
            case IN_PARAMS:
                // This is a hack but at least it matches DataBinder, WebDataBinder, WebRequestDataBinder, etc. all of which are valid here.
                if (stringValue != null && stringValue.endsWith(DATA_BINDER)) {
                    currentState = State.GET_NEXT_STRING;
                } else if (parenCount == 0 && type == OPEN_CURLY) { // this means that the method body has started and WebDataBinder wasn't found
                    currentState = State.IN_CLASS_BODY;
                }
                break;
            case GET_NEXT_STRING:
                if (stringValue != null) {
                    dataBinderName = stringValue;
                    currentState = State.METHOD_BODY;
                } else {
                    currentState = State.IN_CLASS_BODY;
                }
                break;
            case METHOD_BODY:
                if ((dataBinderName + SET_ALLOWED_FIELDS).equals(stringValue)) {
                    currentState = State.GET_WHITELIST;
                } else if ((dataBinderName + SET_DISALLOWED_FIELDS).equals(stringValue)) {
                    currentState = State.GET_BLACKLIST;
                } else if (curlyCount == 0) {
                    currentState = State.IN_CLASS_BODY;
                }
                break;
            case GET_WHITELIST:
                if (type == DOUBLE_QUOTE) {
                    parametersWhiteList.add(stringValue);
                } else if (type == SEMICOLON) {
                    // This might get us into trouble if there are two valid calls in the class
                    // depending on the order in which the methods are defined.
                    // On the other hand, is Spring's behavior defined in that case?
                    hasWhitelist = true;
                    if (hasBlacklist) {
                        shouldContinue = false;
                    } else {
                        currentState = State.METHOD_BODY;
                    }
                }
                break;
            case GET_BLACKLIST:
                if (type == DOUBLE_QUOTE) {
                    parametersBlackList.add(stringValue);
                } else if (type == SEMICOLON) {
                    hasBlacklist = true;
                    if (hasWhitelist) {
                        shouldContinue = false;
                    } else {
                        currentState = State.METHOD_BODY;
                    }
                }
                break;
        }

        switch (type) {
            case '(': parenCount++; break;
            case '{': curlyCount++; break;
            case ')': parenCount--; break;
            case '}': curlyCount--; break;
            default: break; // we don't care
        }
    }

}
