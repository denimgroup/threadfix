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
package com.denimgroup.threadfix.importer.impl.upload.fortify;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.importer.util.RegexUtils;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.importer.impl.upload.fortify.RegexMaps.FACT_REGEX_MAP;

/**
 * Created by mcollins on 2/16/15.
 */
public class DataFlowElementParser {

    static List<DataFlowElement> parseDataFlowElements(
            List<DataFlowElementMap> dataFlowElementMaps,
            FortifyChannelImporter.FortifySAXParser parser) {
        int index = 0;
        String lastNode = null;


        List<DataFlowElement> dataFlowElements = list();

        for (DataFlowElementMap dataFlowElementMap : dataFlowElementMaps) {

            // Don't repeat nodes
            if (lastNode != null && lastNode.equals(dataFlowElementMap.node)) {
                continue;
            }

            // merge results with the information from snippets
            DataFlowElement dataFlowElement = new DataFlowElement();
            if (dataFlowElementMap.node != null) {
                DataFlowElementMap nodeMap = parser.nodeSnippetMap.get(
                        dataFlowElementMap.node);

                if (nodeMap != null) {
                    dataFlowElementMap.merge(nodeMap);
                    lastNode = dataFlowElementMap.node;
                } else {
                    continue;
                }
            }

            // Grab information from the temporary data structure
            if (dataFlowElementMap.snippet != null) {
                dataFlowElement.setLineText(
                        parser.snippetMap.get(dataFlowElementMap.snippet));
            }
            dataFlowElement.setLineNumber(FortifyUtils.getNumber(dataFlowElementMap.line));
            dataFlowElement.setColumnNumber(FortifyUtils.getNumber(dataFlowElementMap.column));

            if (dataFlowElementMap.fileName != null &&
                    !dataFlowElementMap.fileName.trim().equals("")) {
                dataFlowElement.setSourceFileName(dataFlowElementMap.fileName);
                parser.currentPath = dataFlowElementMap.fileName;
            }

            if (dataFlowElement.getSourceFileName() == null ||
                    dataFlowElement.getSourceFileName().trim().equals("") ||
                    dataFlowElement.getLineText() == null ||
                    dataFlowElement.getLineText().trim().equals("")) {
                continue;
            }

            dataFlowElement.setSequence(index++);

            // Attempt to parse a parameter
            if (!parser.paramParsed) {

                // First try the given Fact
                if (parser.currentParameter == null &&
                        dataFlowElementMap.snippet != null &&
                        dataFlowElementMap.fact != null) {
                    String line = parser.snippetMap.get(dataFlowElementMap.snippet);

                    if (FACT_REGEX_MAP.containsKey(dataFlowElementMap.fact)) {
                        parser.currentParameter = RegexUtils.getRegexResult(line,
                                FACT_REGEX_MAP.get(dataFlowElementMap.fact));
                    }

                    // Try to get it out by simply looking at the column and grabbing
                    // the parameter if it is alphanumeric
                    if (parser.currentParameter == null &&
                            dataFlowElement.getColumnNumber() != 0) {
                        String fragment = line.substring(dataFlowElement.getColumnNumber() - 1);
                        if (fragment.trim().endsWith(");")) {

                            if (parser.currentParameter == null) {
                                parser.currentParameter = fragment.trim().replaceFirst("\\);$", "");
                                if (!parser.currentParameter.equals(
                                        RegexUtils.getRegexResult(parser.currentParameter, "^([a-zA-Z_0-9]+)$"))) {
                                    parser.currentParameter = null;
                                }
                            }
                        }
                    }
                }

                // Otherwise try to get it out by using information from the Action tag
                // This tag gives the function call and sometimes the position of the
                // parameter.
                if ((parser.currentParameter == null || parser.currentParameter.trim().equals("")) &&
                        dataFlowElementMap.action != null &&
                        dataFlowElementMap.snippet != null) {

                    String line = parser.snippetMap.get(dataFlowElementMap.snippet);
                    String action = dataFlowElementMap.action;

                    if (line != null && action != null) {
                        parser.currentParameter = ParameterParser.getParameterName(action, line, parser);
                    }
                }

                parser.paramParsed = parser.currentParameter != null;

                if (parser.lastLineVariable != null &&
                        parser.currentParameter != null &&
                        parser.lastLineVariable.contains(parser.currentParameter.trim())) {
                    parser.currentParameter = null;
                }

                if (!parser.paramParsed && dataFlowElementMap.snippet != null) {
                    parser.lastLineVariable = RegexUtils.getRegexResult(
                            parser.snippetMap.get(dataFlowElementMap.snippet), "^([^=]+)=");
                    if (parser.lastLineVariable != null) {
                        parser.lastLineVariable = parser.lastLineVariable.trim();
                    }
                }
            }

            dataFlowElements.add(dataFlowElement);
        }

        parser.paramParsed = false;

        return dataFlowElements;
    }
}
