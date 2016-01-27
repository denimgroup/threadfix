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

package com.denimgroup.threadfix.remote.response;

import com.google.gson.*;

import java.lang.reflect.Type;
import java.util.Calendar;
import java.util.Date;

/**
 * Created by mac on 1/23/14.
 */
public class DateSerializer implements JsonSerializer<Date>, JsonDeserializer<Date> {

    @Override
    public JsonElement serialize(Date src, Type typeOfSrc,	JsonSerializationContext context) {
        return new JsonPrimitive(src.getTime());
    }

    @Override
    public Date deserialize(JsonElement json, Type typeOfT,  JsonDeserializationContext context) throws JsonParseException {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(json.getAsJsonPrimitive().getAsLong());
        return cal.getTime();
    }
}