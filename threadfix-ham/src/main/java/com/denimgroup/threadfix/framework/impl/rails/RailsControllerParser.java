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

import com.denimgroup.threadfix.framework.impl.rails.model.RailsController;
import com.denimgroup.threadfix.framework.impl.rails.model.RailsControllerMethod;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.io.filefilter.WildcardFileFilter;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.StreamTokenizer;
import java.util.*;

/**
 * Created by sgerick on 4/23/2015.
 */
public class RailsControllerParser implements EventBasedTokenizer {

    private static final SanitizedLogger LOG = new SanitizedLogger("RailsParser");

    private enum ControllerState {
        INIT, CLASS, METHOD, PARAMS
    }


    private Deque<String> tokenQueue;
    private boolean _continue;

    private Map<String, List<String>> modelMap;
    private List<RailsController> railsControllers;

    private RailsController currentRailsController;
    private RailsControllerMethod currentCtrlMethod;
    private String currentParamName;

    private ControllerState currentCtrlState = ControllerState.INIT;

    public static Collection parse(@Nonnull File rootFile) {
        if (!rootFile.exists() || !rootFile.isDirectory()) {
            LOG.error("Root file not found or is not directory. Exiting.");
            return null;
        }
        File ctrlDir = new File(rootFile,"app/controllers");
        if (!ctrlDir.exists() || !ctrlDir.isDirectory()) {
            LOG.error("{rootFile}/app/controllers/ not found or is not directory. Exiting.");
            return null;
        }

        Collection<File> rubyFiles = (Collection<File>) FileUtils.listFiles(ctrlDir,
                new WildcardFileFilter("*_controller.rb"), TrueFileFilter.INSTANCE);

        RailsControllerParser parser = new RailsControllerParser();
        parser.modelMap = RailsModelParser.parse(rootFile);
        parser.railsControllers = new ArrayList<>();

        for (File rubyFile : rubyFiles) {
            parser._continue = true;
            parser.tokenQueue = new ArrayDeque<>();
            parser.currentRailsController = null;
            parser.currentCtrlMethod = null;
            parser.currentParamName = null;

            EventBasedTokenizerRunner.runRails(rubyFile, parser);

            if (parser.currentRailsController != null
                    && parser.currentCtrlMethod != null
                    && parser.currentCtrlMethod.getMethodName() != null) {
                parser.currentRailsController.addControllerMethod(parser.currentCtrlMethod);
            }
            if (parser.currentRailsController != null
                    && parser.currentRailsController.getControllerMethods() != null
                    && parser.currentRailsController.getControllerMethods().size() > 0) {
                parser.railsControllers.add(parser.currentRailsController);
            }
        }

        return parser.railsControllers;
    }


    @Override
    public boolean shouldContinue() {
        return _continue;
    }

    @Override
    public void processToken(int type, int lineNumber, String stringValue) {
        String charValue = null;
        if (type > 0)
            charValue = String.valueOf(Character.toChars(type));

        if (stringValue != null) {
            tokenQueue.add(stringValue);
        } else if (charValue != null) {
            tokenQueue.add(charValue);
        }
        if (tokenQueue.size() > 10)
            tokenQueue.remove();

        switch (currentCtrlState) {
            case CLASS:
                processClass(type, stringValue, charValue);
                break;
            case METHOD:
                processMethod(type, stringValue, charValue);
                break;
            case PARAMS:
                processParams(type, stringValue, charValue);
                break;
        }


        if (stringValue != null) {
            switch (stringValue.toLowerCase()) {
                case "private":
                    _continue = false;
                    break;
                case "class":
                    currentCtrlState = ControllerState.CLASS;
                    if (currentRailsController == null)
                        currentRailsController = new RailsController();
                    break;
                case "def":
                    currentCtrlState = ControllerState.METHOD;
                    if (currentCtrlMethod == null)
                        currentCtrlMethod = new RailsControllerMethod();
                    else {
                        currentRailsController.addControllerMethod(currentCtrlMethod);
                        currentCtrlMethod = new RailsControllerMethod();
                    }
                    break;
                case "params":
                    currentCtrlState = ControllerState.PARAMS;
                    break;
            }
        }
    }

    private void processClass(int type, String stringValue, String charValue) {
        if (type == StreamTokenizer.TT_WORD && stringValue != null) {
            String ctrlName = stringValue;
            if (ctrlName.endsWith("Controller")) {
                int i = ctrlName.lastIndexOf("Controller");
                ctrlName = ctrlName.substring(0, i);
            }
            currentRailsController.setControllerName(ctrlName);
            currentCtrlState = ControllerState.INIT;
        }
    }

    private void processMethod(int type, String stringValue, String charValue) {
        if (type == StreamTokenizer.TT_WORD && stringValue != null) {
            currentCtrlMethod.setMethodName(stringValue);
            currentCtrlState = ControllerState.INIT;
        }
    }

    private void processParams(int type, String stringValue, String charValue) {
        if (type == StreamTokenizer.TT_WORD && stringValue.startsWith(":")
                && stringValue.length() > 1) {
            stringValue = stringValue.substring(1);
            // addMethodParam(stringValue);
            if (currentParamName == null)
                currentParamName = stringValue;
            else
                currentParamName = currentParamName.concat(".").concat(stringValue);
            return;
        } else if ("[".equals(charValue) || "]".equals(charValue)) {
            return;
        } else {
            addMethodParam(currentParamName);
            currentParamName = null;
            currentCtrlState = ControllerState.INIT;
            return;
        }

    }

    private void addMethodParam(String stringValue) {
        for (String s : tokenQueue) {   //  .new .create, Model.attr1, Model.attr2
            if ((s.endsWith(".new") || s.endsWith(".create"))
                    && s.toLowerCase().startsWith(stringValue)) {
                for (String p : modelMap.get(stringValue)) {
                    String param = stringValue.concat(".").concat(p);
                    if (currentCtrlMethod.getMethodParams() == null
                            || !currentCtrlMethod.getMethodParams().contains(param)) {
                        currentCtrlMethod.addMethodParam(param);
                    }
                }
                return;
            }
        }
        if (currentCtrlMethod.getMethodParams() == null
                || !currentCtrlMethod.getMethodParams().contains(stringValue)) {
            currentCtrlMethod.addMethodParam(stringValue);
        }
    }

}
