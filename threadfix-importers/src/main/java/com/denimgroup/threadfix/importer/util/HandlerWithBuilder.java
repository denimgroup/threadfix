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
package com.denimgroup.threadfix.importer.util;

import javax.xml.stream.events.StartDocument;

import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public abstract class HandlerWithBuilder extends DefaultHandler {
	protected StringBuilder builder = new StringBuilder();

	protected void addTextToBuilder(char ch[], int start, int length) {
		builder.append(ch, start, length);
	}
	
	protected String getBuilderText() {
    	String toReturn = builder.toString();
    	builder.setLength(0);
    	return toReturn;
    }
	
	//used for synthesizing raw XML from SAX startElement events
    protected String makeTag(String name, String qName, Attributes attrs){
	    
    	StringBuffer tag = new StringBuffer();
        try {
            tag.append("<");
            if (name != null && name.length()>0){
                tag.append(URLEncoder.encode(name, "UTF-8"));
            } else {
                tag.append(URLEncoder.encode(qName, "UTF-8"));
            }

            for (int i = 0; i < attrs.getLength(); i++){
                tag.append(" ");
                tag.append(URLEncoder.encode(attrs.getQName(i), "UTF-8"));
                tag.append("=\"");
                //this will probably need entity encoding
                tag.append(URLEncoder.encode(attrs.getValue(i), "UTF-8"));
                tag.append("\"");
            }
        } catch (UnsupportedEncodingException e) {
            // we should make threadfix die at this point
            throw new RuntimeException("UTF-8 was not supported.", e);
        }
    	
    	tag.append(">");
    	return tag.toString();
    }

	
}
