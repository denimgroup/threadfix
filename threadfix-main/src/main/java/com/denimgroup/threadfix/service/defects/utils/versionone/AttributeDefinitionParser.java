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
package com.denimgroup.threadfix.service.defects.utils.versionone;

import com.denimgroup.threadfix.exception.DefectTrackerFormatException;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

import java.io.*;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 7/7/14.
 */
public class AttributeDefinitionParser extends DefaultHandler {

    List<AttributeDefinition> attributeList = list();
    private AttributeDefinition lastDefinition;

    public static List<AttributeDefinition> parseRequiredAttributes(String inputString) {
        AttributeDefinitionParser parser = new AttributeDefinitionParser();

        try {
            XMLReader xmlReader = XMLReaderFactory.createXMLReader();
            xmlReader.setContentHandler(parser);
            xmlReader.setErrorHandler(parser);

            InputSource source = new InputSource(new StringReader(inputString));
            source.setEncoding("UTF-8");
            xmlReader.parse(source);
        } catch (SAXException | IOException e) {
            throw new DefectTrackerFormatException(e, "Unable to parse server response as XML.");
        }

        return parser.attributeList;
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        if ("AttributeDefinition".equals(qName)) {
            String readonly = attributes.getValue(AttributeDefinition.READONLY_KEY);

            if (readonly != null && readonly.equals("False")) {
                AttributeDefinition definition = new AttributeDefinition(attributes);
                attributeList.add(definition);
                lastDefinition = definition;
            }
        } else if (lastDefinition != null && "RelatedAsset".equals(qName)) {
            lastDefinition.setRelatedItemType(attributes.getValue("nameref"));
            lastDefinition = null; // we don't want to set this twice
        }
    }
}
