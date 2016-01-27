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
package com.denimgroup.threadfix.csv2ssl.util;

/**
 * Created by mac on 12/5/14.
 */
public class Option<T> {

    private final T value;
    private final String error;

    public T getValue() {
        if (value == null) {
            throw new IllegalStateException("getValue() called on error option. Check using isValid() first.");
        }
        return value;
    }

    public String getErrorMessage() {
        if (error == null) {
            throw new IllegalStateException("getErrorMessage() called with no error message.");
        }
        return error;
    }

    public boolean isValid() {
        return value != null;
    }

    private Option(T value, String error) {
        this.value = value;
        this.error = error;
    }

    public static <T> Option<T> failure(String error) {
        if (error == null) {
            throw new IllegalArgumentException("Null passed as argument to Either.failure()");
        }

        return new Option<T>(null, error);
    }

    public static <T, E> Option<T> success(T value) {
        if (value == null) {
            throw new IllegalArgumentException("Null passed as argument to Either.success()");
        }

        return new Option<T>(value, null);
    }

    public Option<T> orElse(T t) {
        return isValid() ? this : new Option<T>(t, null);
    }

    public String toString() {
        if (isValid()) {
            return "Some[" + value + "]";
        } else {
            return "None";
        }
    }

}
