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
    @SafeVarargs
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
    @SafeVarargs
    @Nonnull
    public static <T> Set<T> set(T... args) {
        return new HashSet<T>(Arrays.asList(args));
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
    public static <T> String join(String separator, List<T> args) {
        StringBuilder builder = new StringBuilder();

        for (T project : args) {
            builder.append(project);
            builder.append(separator);
        }

        if (builder.length() > 0) {
            return builder.substring(0, builder.length() - 1);
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
    public static <K, V> Map<K, V> newMap() {
        return new HashMap<K, V>();
    }
}
