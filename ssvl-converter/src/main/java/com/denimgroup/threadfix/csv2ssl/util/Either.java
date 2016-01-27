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

// This class cuts down on nasty null handling. It's a simplified version of the scala Option[T] type.
// When an NPE is encountered, switching to this class makes the compiler work for you
// in ensuring that null is not present.
public class Either<T, E> {

    private final T value;
    private final E error;

    public T getValue() {
        if (value == null) {
            throw new IllegalStateException("getValue() called on error option. Check using isValid() first.");
        }
        return value;
    }

    public E getErrorMessage() {
        if (error == null) {
            throw new IllegalStateException("getErrorMessage() called with no error message.");
        }
        return error;
    }

    public boolean isValid() {
        return value != null;
    }

    protected Either(T value, E error) {
        this.value = value;
        this.error = error;
    }

    public static <T, E> Either<T, E> failure(E error) {
        if (error == null) {
            throw new IllegalArgumentException("Null passed as argument to Either.failure()");
        }

        return new Either<T, E>(null, error);
    }

    public static <T, E> Either<T, E> success(T value) {
        if (value == null) {
            throw new IllegalArgumentException("Null passed as argument to Either.success()");
        }

        return new Either<T, E>(value, null);
    }

    public Either<T, E> orElse(T t) {
        return isValid() ? this : new Either<T, E>(t, null);
    }

}
