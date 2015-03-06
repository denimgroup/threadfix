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
package com.denimgroup.threadfix.importer.impl.upload.fortify;

import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import java.util.EnumMap;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by mcollins on 3/5/15.
 */
public class FilterTemplateXmlParser extends HandlerWithBuilder {

    private String currentUUID = null;
    private Map<String, String> uuidToSeverityMap = newMap();
    private boolean getName = false, inActiveFilter = false;

    Map<String, FilterKey> keyMap = map(
            "actionParam", FilterKey.ACTION_PARAM,
            "query", FilterKey.QUERY,
            "action", FilterKey.ACTION
    );
    FilterKey currentKey = null;

    Map<FilterKey, String> currentFilterMap = new EnumMap<>(FilterKey.class);

    public FortifyFilterSet filterSet = new FortifyFilterSet();

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes)
            throws SAXException {

        if ("FolderDefinition".equals(qName)) {
            currentUUID = attributes.getValue("id");
        } else if (currentUUID != null && "name".equals(qName)) {
            getName = true;
        } else if ("FilterSet".equals(qName)) {
            inActiveFilter = "true".equals(attributes.getValue("enabled"));
        } else if (inActiveFilter && keyMap.containsKey(qName)) {
            currentKey = keyMap.get(qName);
        }
    }

    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {

        if (getName) {
            String name = getBuilderText();

            uuidToSeverityMap.put(currentUUID, name.trim());
            currentUUID = null;
            getName = false;
        } else if (currentKey != null) {

            String value = getBuilderText();

            if (currentKey == FilterKey.ACTION && "setFolder".equals(value)) {

                String severity = uuidToSeverityMap.get(currentFilterMap.get(FilterKey.ACTION_PARAM));
                currentFilterMap.put(FilterKey.SEVERITY, severity);

                FortifyFilter newFilter = new FortifyFilter(currentFilterMap);
                filterSet.addFilter(newFilter);

                currentFilterMap.clear();
            } else {
                currentFilterMap.put(currentKey, value);
            }

            currentKey = null;
        }
    }

    @Override
    public void characters(char[] ch, int start, int length) throws SAXException {
        if (getName || currentKey != null) {
            addTextToBuilder(ch, start, length);
        }
    }
}
