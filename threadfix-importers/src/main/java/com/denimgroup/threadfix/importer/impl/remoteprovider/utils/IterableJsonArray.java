package com.denimgroup.threadfix.importer.impl.remoteprovider.utils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Iterator;

/**
 * Created by mcollins on 1/5/15.
 */
public class IterableJSONArray implements Iterable<JSONObject> {

    public final JSONArray array;

    public IterableJSONArray(String jsonString) throws JSONException {
        array = new JSONArray(jsonString);
    }

    @Override
    public Iterator<JSONObject> iterator() {
        return new Iterator<JSONObject>() {

            int index = 0;

            @Override
            public boolean hasNext() {
                return index < array.length();
            }

            @Override
            public JSONObject next() {
                try {
                    return array.getJSONObject(index++);
                } catch (JSONException e) {
                    throw new ArrayIndexOutOfBoundsException();
                }
            }

            @Override
            public void remove() {
                index++;
            }
        };
    }
}
