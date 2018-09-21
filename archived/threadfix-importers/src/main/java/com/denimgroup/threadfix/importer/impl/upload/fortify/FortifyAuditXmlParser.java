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

import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.xml.sax.Attributes;

import java.util.Calendar;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mcollins on 2/16/15.
 */
class FortifyAuditXmlParser extends HandlerWithBuilder {
    Calendar resultTime = null;
    boolean getDate = false;

    String lastId;

    Set<String> suppressedIds = set();
    private boolean getValue;

    public void startElement (String uri, String name,
                              String qName, Attributes atts)
    {
        if ("WriteDate".equals(name)) {
            getDate = true;
        } else if ("Issue".equals(name)) {
            String instanceId = atts.getValue("instanceId");
            boolean suppressed = "true".equals(atts.getValue("suppressed"));
            if (suppressed && instanceId != null) {
                suppressedIds.add(instanceId);
                lastId = null;
            } else {
                lastId = instanceId;
            }
        } else if ("Value".equals(name)) {
            getValue = true;
        }
    }

    public void endElement(String uri, String name, String qName) {
        if (getDate) {
            String stringTime = getBuilderText();
            if (stringTime != null) {
                int index = stringTime.indexOf('.');
                if (index != -1) {
                    resultTime = DateUtils.getCalendarFromString("yyyy-MM-dd'T'hh:mm:ss",
                            stringTime.substring(0, index));
                }
            }
            getDate = false;
        } else if (getValue) {
            getValue = false;
            if (getBuilderText().equals("Not an Issue")) {
                suppressedIds.add(lastId);
            }
        }
    }

    public void characters (char ch[], int start, int length) {
        if (getDate || getValue) {
            addTextToBuilder(ch, start, length);
        }
    }
}