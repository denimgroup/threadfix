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
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 9/3/14.
 */
public class AspxParser implements EventBasedTokenizer {

    public static final SanitizedLogger LOG = new SanitizedLogger(AspxParser.class);

    public final List<String> ids = list();
    public final String aspName;
    public final File file;
    public List<String> parameters = list();

    @Nonnull
    public static AspxParser parse(@Nonnull File file) {
        AspxParser parser = new AspxParser(file);
        EventBasedTokenizerRunner.run(file, parser);
        return parser;
    }

    AspxParser(File file) {
        LOG.debug("Parsing controller mappings for " + file.getAbsolutePath());
        aspName = file.getName();
        this.file = file;
    }

    @Override
    public boolean shouldContinue() {
        return true;
    }

    enum State {
        OUT_OF_TAG, IN_TAG, ID, EQUALS
    }

    private State state = State.OUT_OF_TAG;

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {

        processRequest(type, lineNumber, stringValue);

        switch (state) {
            case OUT_OF_TAG:
                if (type == '<') {
                    state = State.IN_TAG;
                }
                break;
            case IN_TAG:
                if (type == '>') {
                    state = State.OUT_OF_TAG;
                } else if (stringValue != null && stringValue.toLowerCase().equals("id")) {
                    state = State.ID;
                }
                break;
            case ID:
                if (type == '=') {
                    state = State.EQUALS;
                }
                break;
            case EQUALS:
                if (stringValue != null) {
                    ids.add(stringValue);
                    state = State.IN_TAG;
                }
                break;
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////
    //                       Method-level Request[]-style parsing
    ////////////////////////////////////////////////////////////////////////////////////

    enum RequestState {
        START, ANGLE, PERCENT, EQUALS, REQUEST, OPEN_SQUARE
    }
    RequestState requestState = RequestState.START;

    private void processRequest(int type, int lineNumber, String stringValue) {
        switch (requestState) {
            case START:
                requestState = type == '<' ? RequestState.ANGLE : RequestState.START;
                break;
            case ANGLE:
                requestState = type == '%' ? RequestState.PERCENT : RequestState.START;
                break;
            case PERCENT:
                requestState = type == '=' ? RequestState.EQUALS : RequestState.START;
                break;
            case EQUALS:
                if (type == -3 && stringValue.equals("Request")) {
                    requestState = RequestState.REQUEST;
                } else if (type == '>') {
                    requestState = RequestState.START;
                }
                break;
            case REQUEST:
                requestState = type == '[' ? RequestState.OPEN_SQUARE : RequestState.EQUALS;
                break;
            case OPEN_SQUARE:
                if (type == '"') {
                    parameters.add(stringValue);
                }
                requestState = RequestState.EQUALS;
                break;
        }
    }

    @Override
    public String toString() {
        return "AspxParser{" +
                aspName + ": " + ids +
                '}';
    }
}
