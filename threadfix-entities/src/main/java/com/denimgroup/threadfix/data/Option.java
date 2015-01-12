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
package com.denimgroup.threadfix.data;

// This class cuts down on nasty null handling. It's a simplified version of the scala Option[T] type.
// When an NPE is encountered, switching to this class makes the compiler work for you
// in ensuring that null is not present.
public class Option<T> {

    private final T value;

    public T getValue() {
        assert value != null;
        return value;
    }

    public boolean isValid() {
        return value != null;
    }

    private Option(T value) {
        this.value = value;
    }

    public static <T> Option<T> failure() {
        return new Option<T>(null);
    }

    public static <T> Option<T> success(T value) {
        return new Option<T>(value);
    }

    public Option<T> orElse(T t) {
        return isValid() ? this : new Option<T>(t);
    }

}
