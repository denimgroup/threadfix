package com.denimgroup.threadfix.remote.response;

import com.google.gson.*;
import org.apache.commons.codec.binary.Base64;

import java.lang.reflect.Type;

/**
 * Created by mac on 1/29/14.
 */
public class ByteToStringSerializer implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {

    @Override
    public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        return Base64.decodeBase64(json.getAsString().getBytes());
    }

    @Override
    public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
        return new JsonPrimitive(new String(src));
    }

}
