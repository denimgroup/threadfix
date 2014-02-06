package com.denimgroup.threadfix.remote.response;

import com.google.gson.*;

import java.lang.reflect.Type;
import java.util.Calendar;

/**
 * Created by mac on 1/23/14.
 */
public class CalendarSerializer implements JsonSerializer<Calendar>, JsonDeserializer<Calendar> {

    @Override
    public JsonElement serialize(Calendar src, Type typeOfSrc,	JsonSerializationContext context) {
        return new JsonPrimitive(src.getTimeInMillis());
    }

    @Override
    public Calendar deserialize(JsonElement json, Type typeOfT,  JsonDeserializationContext context) throws JsonParseException {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(json.getAsJsonPrimitive().getAsLong());
        return cal;
    }
}