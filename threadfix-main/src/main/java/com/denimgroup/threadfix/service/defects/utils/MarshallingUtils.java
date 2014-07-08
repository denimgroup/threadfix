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
