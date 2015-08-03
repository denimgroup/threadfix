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
package com.denimgroup.threadfix.util;

import java.util.Iterator;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.util.Tuple.tuple;

/**
 * This is like a Map<A, B>
 * It is not efficient! Don't use it when performance is important
 * Created by mcollins on 8/3/15.
 */
public class TupleSet<A, B> implements Iterable<Tuple<A, B>> {

    List<Tuple<A, B>> backingList = list();

    public void add(A a, B b) {
        backingList.add(tuple(a, b));
    }

    /**
     * Yes, O(n) algorithm for contains
     */
    public boolean containsKey(A a) {
        for (Tuple<A, B> tuple : backingList) {
            if (tuple.getFirst().equals(a)) {
                return true;
            }
        }

        return false;
    }

    public B get(A a) {
        for (Tuple<A, B> tuple : backingList) {
            if (tuple.getFirst().equals(a)) {
                return tuple.getSecond();
            }
        }

        return null;
    }

    public static <A, B> TupleSet<A, B> tupleSet() {
        return new TupleSet<A, B>();
    }

    public int size() {
        return backingList.size();
    }

    @Override
    public Iterator<Tuple<A, B>> iterator() {
        return backingList.iterator();
    }

    @Override
    public String toString() {
        return backingList.toString();
    }
}
