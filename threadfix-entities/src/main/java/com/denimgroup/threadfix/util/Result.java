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
package com.denimgroup.threadfix.util;

/**
 * Created by mcollins on 7/27/15.
 */
public class Result<T> {

    T result = null;
    String errorMessage = null;
    boolean success = false;

    public T getResult() {
        if (result == null) {
            throw new IllegalStateException("Check valid status before calling getResult()");
        }
        return result;
    }

    public String getErrorMessage() {
        if (errorMessage == null) {
            throw new IllegalStateException("Check valid status before calling getErrorMessage()");
        }
        return errorMessage;
    }

    public boolean success() {
        return success;
    }

    private Result() {}

    public static <T> Result<T> failure(String message) {
        if (message == null) {
            throw new IllegalArgumentException("Can't pass null message.");
        }

        Result<T> result = new Result<T>();
        result.errorMessage = message;
        return result;
    }

    public static <T> Result<T> success(T resultObject) {
        if (resultObject == null) {
            throw new IllegalArgumentException("Can't pass null message.");
        }

        Result<T> result = new Result<T>();
        result.success = true;
        result.result = resultObject;
        return result;
    }

    @Override
    public String toString() {
        if (success) {
            return result.toString();
        } else {
            return "Failure: " + errorMessage;
        }
    }

}
