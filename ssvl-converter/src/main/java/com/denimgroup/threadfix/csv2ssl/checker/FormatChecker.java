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
package com.denimgroup.threadfix.csv2ssl.checker;

import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Created by mac on 12/2/14.
 */
public class FormatChecker {

    public FormatChecker() {}

    public static boolean checkFormat(String input) {
        try {
            URL schemaFile = FormatChecker.class.getClassLoader().getResource("ssvl.xsd");

            if (schemaFile == null) {
                throw new IllegalStateException("ssvl.xsd file not available from ClassLoader. Fix that.");
            }

            if (input == null) {
                throw new IllegalArgumentException("inputFileName was null, unable to load scan file.");
            }

            Source xmlFile = new StreamSource(new StringReader(input));
            SchemaFactory schemaFactory = SchemaFactory
                    .newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = schemaFactory.newSchema(schemaFile);
            Validator validator = schema.newValidator();
            validator.validate(xmlFile);

            return true;
        } catch (MalformedURLException e) {
            System.out.println("Code contained an incorrect path to the XSD file.");
            e.printStackTrace();
            assert false : "Got MalformedURLException";
        } catch (SAXException e) {
            System.out.println("SAX Exception encountered.");
            e.printStackTrace();
            assert false : "Got SAXException";
        } catch (IOException e) {
            System.out.println("IOException encountered.");
            e.printStackTrace();
            assert false : "Got IOException";
        }

        return false;
    }


}
