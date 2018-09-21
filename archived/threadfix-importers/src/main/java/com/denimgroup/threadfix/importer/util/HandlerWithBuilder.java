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
package com.denimgroup.threadfix.importer.util;

import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

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
	    
    	StringBuilder tag = new StringBuilder();

        tag.append("<");

        if (name != null && name.length()>0){
            tag.append(name);
        } else {
            tag.append(qName);
        }

        if (attrs != null) {
            for (int i = 0; i < attrs.getLength(); i++) {
                tag.append(" ");
                tag.append(attrs.getQName(i));
                tag.append("=\"");
                //this will probably need entity encoding
                tag.append(attrs.getValue(i));
                tag.append("\"");
            }
        }

    	tag.append(">");
    	return tag.toString();
    }

	//used for synthesizing raw XML from SAX startElement events
    protected String makeEndTag(String name, String qName){

    	StringBuilder tag = new StringBuilder();

        tag.append("</");

        if (name != null && name.length()>0){
            tag.append(name);
        } else {
            tag.append(qName);
        }

    	tag.append(">");
    	return tag.toString();
    }

	
}
