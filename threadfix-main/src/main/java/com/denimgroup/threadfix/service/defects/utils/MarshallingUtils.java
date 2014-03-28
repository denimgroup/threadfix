package com.denimgroup.threadfix.service.defects.utils;

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
     * @throws javax.xml.bind.JAXBException
     */
    @SuppressWarnings("unchecked")
    public static <T> T marshal(Class<T> c, String xml) throws JAXBException {
        T res;

        if (c == xml.getClass()) {
            res = (T) xml;
        }

        else {
            JAXBContext ctx = JAXBContext.newInstance(c);
            Unmarshaller marshaller = ctx.createUnmarshaller();
            res = (T) marshaller.unmarshal(new StringReader(xml));
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
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public static <T> String unmarshal(Class<T> c, Object o) throws Exception {

        JAXBContext ctx = JAXBContext.newInstance(c);
        Marshaller marshaller = ctx.createMarshaller();
        StringWriter entityXml = new StringWriter();
        marshaller.marshal(o, entityXml);

        String entityString = entityXml.toString();

        return entityString;
    }

}
