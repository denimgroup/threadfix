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
package com.denimgroup.threadfix.importer.impl.remoteprovider.realtimeprovider.utils;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;
import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;

public class FortifySscClient {

    private URL endpointUrl;
    private String sscToken;
    private String sscUsername;
    private String sscPassword;

    /**
     * Constructs a new FortifySscClient object using traditional username/password authentication
     *
     * @param endpointUrl The URL to the Fortify SSC server's SOAP endpoint
     * @param sscUsername The username to authenticate with
     * @param sscPassword The password to authenticate with
     */
    public FortifySscClient(URL endpointUrl, String sscUsername, String sscPassword) {
        this.endpointUrl = endpointUrl;
        this.sscUsername = sscUsername;
        this.sscPassword = sscPassword;
    }

    /**
     * Constructs a new FortifySscClient object using traditional username/password authentication
     *
     * @param endpointUrl The URL to the Fortify SSC server's SOAP endpoint
     * @param sscToken    The token to authenticate with
     */
    public FortifySscClient(URL endpointUrl, String sscToken) {
        this.endpointUrl = endpointUrl;
        this.sscToken = sscToken;
    }

    /**
     * Create a new SOAP message from the specified XMLBeans object. The XmlObject
     * will be injected into the SOAP Body.
     *
     * @param xmlObject The XmlObject to create a SOAP message from
     * @return a SOAPMessage containing the contents of the specified XmlObject
     * @throws javax.xml.soap.SOAPException
     */
    public SOAPMessage createSoapMessage(XmlObject xmlObject) throws SOAPException {
        MessageFactory msgFactory = MessageFactory.newInstance();

        SOAPMessage soapMessage = msgFactory.createMessage();
        SOAPPart prt = soapMessage.getSOAPPart();
        SOAPEnvelope env = prt.getEnvelope();
        addWssHeader(env);
        SOAPBody soapBody = env.getBody();

        org.w3c.dom.Node node = xmlObject.getDomNode();
        soapBody.addDocument((Document) node);
        return soapMessage;
    }

    /**
     * Adds a webservices security header containing username/password credentials and
     * optionally a Fortify authentication token
     *
     * @param envelope The soap envelope to add the header to
     * @throws javax.xml.soap.SOAPException
     */
    private void addWssHeader(SOAPEnvelope envelope) throws SOAPException {
        SOAPHeader header;
        if (envelope.getHeader() == null)
            header = envelope.addHeader();
        else
            header = envelope.getHeader();

        if (sscToken != null) {
            header.addAttribute(new QName("xmlns:axis2ns2"), "www.fortify.com/schema");
            header.addAttribute(new QName("axis2ns2:token"), sscToken);
        }

        SOAPElement security = header.addChildElement("Security", "wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");

        SOAPElement usernameToken = security.addChildElement("UsernameToken", "wsse");
        usernameToken.addAttribute(new QName("xmlns:wsu"), "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

        SOAPElement username = usernameToken.addChildElement("Username", "wsse");
        if (sscUsername != null) {
            username.addTextNode(sscUsername);
        }

        SOAPElement password = usernameToken.addChildElement("Password", "wsse");
        password.setAttribute("Type", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText");
        if (sscPassword != null) {
            password.addTextNode(sscPassword);
        }
    }

    /**
     * Makes a remote call to the SOAP endpoint.
     *
     * @param soapMessage The SOAP message to send to the endpoint
     * @return a SOAPMessage as a response
     * @throws javax.xml.soap.SOAPException
     * @throws java.io.IOException
     */
    public SOAPMessage callEndpoint(SOAPMessage soapMessage) throws SOAPException, IOException {
        SOAPConnectionFactory fact;
        fact = SOAPConnectionFactory.newInstance();
        SOAPConnection con = fact.createConnection();
        SOAPMessage response = con.call(soapMessage, endpointUrl);
        con.close();
        return response;
    }

    /**
     * Parses a SOAP message using XMLBeans and casting the resulting XmlObject to
     * the specified XmlObject implementation class.
     *
     * @param soapMessage The SOAP message to parse
     * @param clazz       The XmlObject class (in XMLBeans) for parsing and casting
     * @return A parsed SOAP message as a XmlObject implementation
     */
    public <T> T parseMessage(SOAPMessage soapMessage, Class<T> clazz)
            throws SOAPException, XmlException, NoSuchFieldException, IllegalAccessException, JAXBException, TransformerException {


        XmlObject b = XmlObject.Factory.parse(soapMessage.getSOAPBody().getFirstChild());
        Field typeField = clazz.getDeclaredField("type");
        org.apache.xmlbeans.SchemaType schemaType = (org.apache.xmlbeans.SchemaType) typeField.get(null);
        XmlObject c = org.apache.xmlbeans.XmlBeans.getContextTypeLoader().parse(b.getDomNode(), schemaType, null);


        return clazz.cast(c);
    }

}
