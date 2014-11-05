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
 * Created by mac on 10/20/14.
 */
public class AspxUniqueIdParser implements EventBasedTokenizer {

    private static final SanitizedLogger LOG = new SanitizedLogger(AspxUniqueIdParser.class);
    private final AspxControlStack aspxControlStack = new AspxControlStack();;
    Set<String> parameters = set();
    Set<String> tagsThatGenerateParameters = set(
            "asp:BoundField", "asp:TextBox"
    ); // TODO figure this out better

    String masterPage = null;

    private Map<String, AscxFile> allControlMap;

    @Nonnull
    public static AspxUniqueIdParser parse(@Nonnull File file) {
        return runTokenizer(file, new AspxUniqueIdParser(file));
    }

    @Nonnull
    public static AspxUniqueIdParser parse(@Nonnull File file, Map<String, AscxFile> controlMap) {
        return runTokenizer(file, new AspxUniqueIdParser(file, controlMap));
    }

    private static AspxUniqueIdParser runTokenizer(File file, AspxUniqueIdParser parser) {
        EventBasedTokenizerRunner.run(file, false, parser);
        return parser;
    }

    final String name;

    AspxUniqueIdParser(File file) {
        assert file.exists() : "File didn't exist.";
        assert file.isFile() : "File was not a valid file.";
        LOG.debug("Parsing controller mappings for " + file.getAbsolutePath());
        name = file.getName();
    }


    AspxUniqueIdParser(File file, Map<String, AscxFile> controlMap) {
        assert file.exists() : "File didn't exist.";
        assert file.isFile() : "File was not a valid file.";
        LOG.debug("Parsing controller mappings for " + file.getAbsolutePath());
        name = file.getName();
        this.allControlMap = controlMap;
    }

    @Override
    public boolean shouldContinue() {
        return true;
    }

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {
        processMasterPage(type, stringValue);
        processRequires(type, stringValue);
        processBody(type, stringValue);
        processCustomTags(type, stringValue);
        printDebug(type, lineNumber, stringValue);
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                       Parse <@% Page statements
    //////////////////////////////////////////////////////////////////////////////////////////

    private enum PageState {
        START, LEFT_ANGLE, PERCENT, ARROBA, PAGE, MASTER_PAGE_FILE, DONE
    }
    PageState currentPageState = PageState.START;

    private void processMasterPage(int type, String stringValue) {
        switch (currentPageState) {
            case START:
                currentPageState = type == '<' ? PageState.LEFT_ANGLE : PageState.START;
                break;
            case LEFT_ANGLE:
                currentPageState = type == '%' ? PageState.PERCENT : PageState.START;
                break;
            case PERCENT:
                currentPageState = type == '@' ? PageState.ARROBA : PageState.START;
                break;
            case ARROBA:
                currentPageState = type == -3 && "Page".equals(stringValue) ? PageState.PAGE : PageState.START;
                break;
            case PAGE:
                if (type == '>') {
                    currentPageState = PageState.DONE;
                } else if ("MasterPageFile".equals(stringValue)) {
                    currentPageState = PageState.MASTER_PAGE_FILE;
                }
                break;
            case MASTER_PAGE_FILE:
                if (type == '"') {
                    masterPage = stringValue.startsWith("~/") ? stringValue.substring(2) : stringValue;
                } else if (type != '=') {
                    currentPageState = PageState.DONE;
                }
                break;
            case DONE:
                break;
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                       Parse <@% Require statements
    //////////////////////////////////////////////////////////////////////////////////////////

    private enum State {
        START, LEFT_ANGLE, PERCENT, ARROBA, REGISTER, SRC, TAG_PREFIX, TAG_NAME
    }
    State currentState = State.START;
    String currentSrc, currentTagPrefix, currentTagName;
    Map<String, AscxFile> includedControlMap = newMap();

    private void processRequires(int type, String stringValue) {
        switch (currentState) {
            case START:
                currentState = type == '<' ? State.LEFT_ANGLE : State.START;
                break;
            case LEFT_ANGLE:
                currentState = type == '%' ? State.PERCENT : State.START;
                break;
            case PERCENT:
                currentState = type == '@' ? State.ARROBA : State.START;
                break;
            case ARROBA:
                currentState = "Register".equals(stringValue) ? State.REGISTER : State.START;
                break;
            case REGISTER:
                if (type == '>') {
                    saveControlData();
                    currentState = State.START;
                } else if ("Src".equals(stringValue)) {
                    currentState = State.SRC;
                } else if ("TagPrefix".equals(stringValue)) {
                    currentState = State.TAG_PREFIX;
                } else if ("TagName".equals(stringValue)) {
                    currentState = State.TAG_NAME;
                }
                break;

            // TODO refactor this?? a little WET
            case SRC:
                if (type == '"') {
                    currentSrc = stringValue;
                }
                if (type != '=') {
                    currentState = State.REGISTER;
                }
                break;
            case TAG_PREFIX:
                if (type == '"') {
                    currentTagPrefix = stringValue;
                }
                if (type != '=') {
                    currentState = State.REGISTER;
                }
                break;
            case TAG_NAME:
                if (type == '"') {
                    currentTagName = stringValue;
                }
                if (type != '=') {
                    currentState = State.REGISTER;
                }
                break;
        }
    }

    private void saveControlData() {
        if (allControlMap != null) {
            AscxFile ascxFile = allControlMap.get(currentTagName);
            if (ascxFile != null) {
                includedControlMap.put(currentTagPrefix + ":" + currentTagName, ascxFile);
            } else {
                LOG.error("Unable to load control " + currentTagName + ".");
            }
        } else {
            LOG.error("Got data for a control but wasn't passed any control definitions.");
        }

        currentTagName = null;
        currentSrc = null;
        currentTagPrefix = null;
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                           Parse custom controls
    //////////////////////////////////////////////////////////////////////////////////////////

    enum ControlState {
        START, LEFT_ANGLE, NAME, ID
    }
    ControlState currentControlState = ControlState.START;
    AscxFile currentFile = null;
    String currentControlTagName = null;

    private void processCustomTags(int type, String stringValue) {
        switch (currentControlState) {
            case START:
                currentControlState = type == '<' ? ControlState.LEFT_ANGLE : ControlState.START;
                break;
            case LEFT_ANGLE:
                if (includedControlMap.containsKey(stringValue)) {
                    currentFile = includedControlMap.get(stringValue);
                    currentControlTagName = stringValue;
                    LOG.info("Got control from file " + currentFile.name);
                    currentControlState = ControlState.NAME;
                } else {
                    currentControlState = ControlState.START;
                }
                break;
            case NAME:
                // -3 is the "token" code
                if (type == -3 && "ID".equals(stringValue)) {
                    currentControlState = ControlState.ID;
                }
                break;
            case ID:
                if (type == '"' && stringValue != null) {
                    addTag(currentControlTagName, stringValue);
                    LOG.info("Expanding control with ID " + stringValue);

                    boolean tempGotId = gotIdAttribute;
                    gotIdAttribute = false; // this prevents a bug during expansion
                    currentFile.expandIn(this);
                    gotIdAttribute = tempGotId; // this replaces to the value it had before expansion

                    removeTag(currentControlTagName, stringValue);

                } else if (type != '=') {
                    currentControlState = ControlState.START;
                }
                break;
        }

        if (type == '>') {
            currentControlTagName = null;
            currentFile = null;
            currentControlState = ControlState.START;
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                             Debug information
    //////////////////////////////////////////////////////////////////////////////////////////

    boolean print = false;

    private void printDebug(int type, int lineNumber, String stringValue) {
        if (print) {
            if (type < 0) {
                LOG.debug("type = " + type);
            } else {
                LOG.debug("type = " + Character.valueOf((char) type));
            }
            LOG.debug("line = " + lineNumber);
            LOG.debug("stringValue = " + stringValue);
            LOG.debug("");
            LOG.debug("currentState = " + currentState);
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                                 Main processing
    //////////////////////////////////////////////////////////////////////////////////////////

    boolean endTag = false, needsId = false, gotIdAttribute = false, hasAdded = false;
    String lastName = null, lastId;
    int lastToken = -10; // out of range for even the token codes in StreamTokenizer

    private void processBody(int type, String stringValue) {
        if (stringValue != null && stringValue.startsWith("asp")) {
            if (endTag) {
                LOG.debug("Ending " + stringValue);
                removeTag(lastName, lastId);
            } else {
                LOG.debug("Starting " + stringValue);
                lastName = stringValue;
                lastId = null;
                needsId = true;
            }
        }

        if (lastName != null && gotIdAttribute && stringValue != null) {
            lastId = stringValue;
            LOG.debug("Adding from here");
            addTag(lastName, lastId);
            hasAdded = true;
            needsId = false;
            gotIdAttribute = false;
        }

        if ("asp:Content".equals(lastName)) {
            gotIdAttribute = gotIdAttribute || (needsId && stringValue != null && stringValue.equals("ContentPlaceHolderID"));
        } else {
            gotIdAttribute = gotIdAttribute || (needsId && stringValue != null && stringValue.equals("ID"));
        }

        if (type == '>' && lastName != null) { // we only want to do this if we're in an asp:* tag
            if (!hasAdded && needsId) {
                LOG.debug("Adding here");
                addTag(lastName, null);
            }

            if (endTag) {
                removeTag(lastName, lastId);
            }

            lastName = null;
            hasAdded = false;
            gotIdAttribute = false;
        }

        endTag = type == '/';
        lastToken = type;
    }

    private void addTag(String name, String id) {
        aspxControlStack.add(new AspxControl(name, id));
    }

    private void removeTag(String name, String id) {
        if (tagsThatGenerateParameters.contains(name)) {
            addCurrentParam();
        }

        aspxControlStack.removeLast();
        lastName = null;
        lastId = null;
    }

    private void addCurrentParam() {
        String newParameter = aspxControlStack.generateCurrentParamName();
        parameters.add(newParameter);
        LOG.debug("After adding " + newParameter + ", parameters contains: " + parameters);
    }
}
