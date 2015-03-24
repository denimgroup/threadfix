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
package com.denimgroup.threadfix;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;

/**
 * Created by mac on 7/3/14.
 */
public class CollectionUtils {

    /**
     *
     * Create a list out of arguments. This is as close to an object literal as you can get in Java and very similar to
     * the scala List()
     *
     * @param args items to put in a list
     * @param <T> type of items
     * @return list of items passed as arguments
     */
    @Nonnull
    public static <T> List<T> list(T... args) {
        if (args.length == 0) {
            // avoid the extra constructor call if we have 0 arguments
            return new ArrayList<T>();
        } else {
            return new ArrayList<T>(Arrays.asList(args));
        }
    }

    public static <T> List<T> listOf(Class<T> targetClass) {
        return new ArrayList<T>();
    }

    /**
     * Provides a wrapper to create a list out of a collection
     * @param wrappedCollection nullable collection
     * @param <T> type parameter of collection and resulting list
     * @return list of Ts from wrappedCollection or empty list
     */
    @Nonnull
    public static <T> List<T> listFrom(@Nullable Collection<T> wrappedCollection) {
        if (wrappedCollection == null || wrappedCollection.isEmpty()) {
            return new ArrayList<T>();
        } else {
            return new ArrayList<T>(wrappedCollection);
        }
    }

    /**
     *
     *
     * Create a set out of arguments. This is as close to an object literal as you can get in Java and very similar to
     * the scala Set()
     *
     * @param args items to put in a set
     * @param <T> type of set
     * @return set of items passed as arguments
     */
    @Nonnull
    public static <T> Set<T> set(T... args) {
        return new HashSet<T>(Arrays.asList(args));
    }


    /**
     *
     * Create a set out of arguments. This is as close to an object literal as you can get in Java and very similar to
     * the scala Set()
     *
     * @param targetCollection items to put in a set
     * @param <T> type of set
     * @return set of items passed as arguments
     */
    @Nonnull
    public static <T> Set<T> setFrom(Collection<T> targetCollection) {
        return new HashSet<T>(targetCollection);
    }

    /**
     *
     * @param separator character to put between arguments
     * @param args items to string together
     * @param <T> type of items
     * @return "" for empty array, otherwise arg1 + separator + arg2 + separator + ...
     */
    @Nonnull
    public static <T> String join(String separator, T... args) {
        return join(separator, Arrays.asList(args));
    }

    /**
     *
     * @param separator character to put between arguments
     * @param args items to string together
     * @param <T> type of items
     * @return "" for empty list, otherwise arg1 + separator + arg2 + separator + ...
     */
    @Nonnull
    public static <T> String join(String separator, Iterable<T> args) {
        StringBuilder builder = new StringBuilder();

        for (T project : args) {
            builder.append(project);
            builder.append(separator);
        }

        if (builder.length() > separator.length()) {
            return builder.substring(0, builder.length() - separator.length());
        } else {
            return "";
        }
    }

    /**
     * This is a convenience method so we can avoid typing angle brackets.
     * @param <K> key type parameter
     * @param <V> value type parameter
     * @return new HashMap<K, V>()
     */
    @Nonnull
    public static <K, V> Map<K, V> map() {
        return new HashMap<K, V>();
    }

    @Nonnull
    public static <K extends Enum<K>, V> Map<K, V> enumMap(Class<K> enumClass) {
        return new EnumMap<K, V>(enumClass);
    }

    /**
     * The following methods all create maps in a Scala Map style.
     * @param key1 first key
     * @param value1 first value
     * @param <K> Key type
     * @param <V> Value type
     * @return map with given keys and values
     */
    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2, K key3, V value3) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2, K key3, V value3, K key4, V value4) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6,
                                       K key7, V value7) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        map.put(key7, value7);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6,
                                       K key7, V value7, K key8, V value8) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        map.put(key7, value7);
        map.put(key8, value8);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6,
                                       K key7, V value7, K key8, V value8,
                                       K key9, V value9) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        map.put(key7, value7);
        map.put(key8, value8);
        map.put(key9, value9);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6,
                                       K key7, V value7, K key8, V value8,
                                       K key9, V value9, K key10, V value10) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        map.put(key7, value7);
        map.put(key8, value8);
        map.put(key9, value9);
        map.put(key10, value10);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6,
                                       K key7, V value7, K key8, V value8,
                                       K key9, V value9, K key10, V value10,
                                       K key11, V value11) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        map.put(key7, value7);
        map.put(key8, value8);
        map.put(key9, value9);
        map.put(key10, value10);
        map.put(key11, value11);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6,
                                       K key7, V value7, K key8, V value8,
                                       K key9, V value9, K key10, V value10,
                                       K key11, V value11, K key12, V value12) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        map.put(key7, value7);
        map.put(key8, value8);
        map.put(key9, value9);
        map.put(key10, value10);
        map.put(key11, value11);
        map.put(key12, value12);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6,
                                       K key7, V value7, K key8, V value8,
                                       K key9, V value9, K key10, V value10,
                                       K key11, V value11, K key12, V value12,
                                       K key13, V value13) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        map.put(key7, value7);
        map.put(key8, value8);
        map.put(key9, value9);
        map.put(key10, value10);
        map.put(key11, value11);
        map.put(key12, value12);
        map.put(key13, value13);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6,
                                       K key7, V value7, K key8, V value8,
                                       K key9, V value9, K key10, V value10,
                                       K key11, V value11, K key12, V value12,
                                       K key13, V value13, K key14, V value14) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        map.put(key7, value7);
        map.put(key8, value8);
        map.put(key9, value9);
        map.put(key10, value10);
        map.put(key11, value11);
        map.put(key12, value12);
        map.put(key13, value13);
        map.put(key14, value14);

        return map;
    }

    @Nonnull
    public static <K, V> Map<K, V> map(K key1, V value1, K key2, V value2,
                                       K key3, V value3, K key4, V value4,
                                       K key5, V value5, K key6, V value6,
                                       K key7, V value7, K key8, V value8,
                                       K key9, V value9, K key10, V value10,
                                       K key11, V value11, K key12, V value12,
                                       K key13, V value13, K key14, V value14,
                                       K key15, V value15) {
        HashMap<K, V> map = new HashMap<K, V>();

        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        map.put(key4, value4);
        map.put(key5, value5);
        map.put(key6, value6);
        map.put(key7, value7);
        map.put(key8, value8);
        map.put(key9, value9);
        map.put(key10, value10);
        map.put(key11, value11);
        map.put(key12, value12);
        map.put(key13, value13);
        map.put(key14, value14);
        map.put(key15, value15);

        return map;
    }



}
