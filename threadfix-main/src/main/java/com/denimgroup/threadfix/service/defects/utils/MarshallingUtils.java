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

package com.denimgroup.threadfix.service.defects.utils;

import com.denimgroup.threadfix.exception.DefectTrackerFormatException;

import javax.annotation.Nonnull;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.io.StringReader;
import java.io.StringWriter;

/**
 * A utility class for converting between jaxb annotated objects and xml.
 */
public class MarshallingUtils {

    private MarshallingUtils() {}

    /**
     * @param <T>
     *            the type we want to convert our xml into
     * @param c
     *            the class of the parameterized type
     * @param xml
     *            the instance xml description
     * @return a deserialization of the xml into an object of type T
     *           of class Class<T>
     */
    @SuppressWarnings("unchecked")
    public static <T> T marshal(Class<T> c, @Nonnull String xml) {
        T res;

        if (c == xml.getClass()) {
            res = (T) xml;
        } else {
            try {
                JAXBContext ctx = JAXBContext.newInstance(c);
                Unmarshaller marshaller = ctx.createUnmarshaller();
                res = (T) marshaller.unmarshal(new StringReader(xml));
            } catch (JAXBException e) {
                throw new DefectTrackerFormatException(e, "Unable to parse XML response from server.");
            }
        }

        return res;
    }

    /**
     * @param <T>
     *            the type to serialize
     * @param c
     *            the class of the type to serialize
     * @param o
     *            the instance containing the data to serialize
     * @return a string representation of the data.
     */
    @SuppressWarnings("unchecked")
    public static <T> String unmarshal(Class<T> c, Object o) {

        try {
            JAXBContext ctx = JAXBContext.newInstance(c);
            Marshaller marshaller = ctx.createMarshaller();
            StringWriter entityXml = new StringWriter();
            marshaller.marshal(o, entityXml);

            return entityXml.toString();
        } catch (JAXBException e) {
            throw new DefectTrackerFormatException(e, "Unable to parse XML response from server.");
        }
    }

}
