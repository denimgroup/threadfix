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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.Event;

import java.util.Comparator;

public class EventComparator implements Comparator<Event> {
    boolean ascending = true;

    public EventComparator() {
        super();
    }

    public EventComparator(boolean ascending) {
        this();
        this.ascending = ascending;
    }

    @Override
    public int compare(Event e1, Event e2) {
        if (ascending) {
            return compareInternal(e1, e2);
        } else {
            return compareInternal(e2, e1);
        }
    }

    public int compareInternal(Event e1, Event e2) {
        Integer compared = compareForNulls(e1, e2);
        if (compared != null) {
            return compared;
        }

        compared = compareTwoComparables(e1.getDate(), e2.getDate());
        if (compared != 0) {
            return compared;
        }

        compared = compareTwoComparables(e1.getEventActionEnum(), e2.getEventActionEnum());
        if (compared != 0) {
            return compared;
        }

        compared = compareTwoComparables(e1.getId(), e2.getId());
        if (compared != 0) {
            return compared;
        }

        compared = compareTwoComparables(e1.hashCode(), e2.hashCode());
        if (compared != 0) {
            return compared;
        }

        if (e1.equals(e2)) {
             return 0;
        }
        return -1;
    }

    private int compareTwoComparables(Comparable o1, Comparable o2) {
        Integer compared = compareForNulls(o1, o2);
        if (compared != null) {
            return compared;
        }
        return o1.compareTo(o2);
    }

    private Integer compareForNulls(Object o1, Object o2) {
        if ((o1 == null) && (o2 == null)) {
            return 0;
        } else if (o1 == null) {
            return -1;
        } else if (o2 == null) {
            return 1;
        }
        return null;
    }
}
