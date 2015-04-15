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
package com.denimgroup.threadfix.framework.impl.spring.auth;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mcollins on 3/31/15.
 */
public class SpringSecurityXmlParser extends DefaultHandler {

    private boolean inHTTP = false;
    public List<InterceptUrl> urls = list();
    public boolean prePostEnabled = false;

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
        if (localName.equals("http")) {
            inHTTP = true;
        } else if (inHTTP && localName.equals("intercept-url")) {
            urls.add(new InterceptUrl(attributes));
        } else if (!inHTTP && localName.equals("global-method-security")) {
            prePostEnabled = "enabled".equals(attributes.getValue("pre-post-annotations"));
        }
    }

    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        if (localName.equals("http")) {
            inHTTP = false;
        }
    }

    @Override
    public String toString() {
        return "pre-post: " + prePostEnabled + ", urls: " + urls;
    }
}
