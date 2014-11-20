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
package com.denimgroup.threadfix.exception;

/**
 * This is an abstract class so that we can intercept it using RestExceptionControllerAdvice
 * Created by mac on 7/3/14.
 */
public abstract class RestException extends RuntimeException {

    final String responseString;

    /**
     *
     * @param cause wrapped exception
     * @param responseString gets printed to the user
     */
    public RestException(Throwable cause, String responseString) {
        super(responseString, cause);
        this.responseString = responseString;
    }

    /**
     *
     * @param responseString gets printed to the user
     */
    public RestException(String responseString) {
        super(responseString);
        this.responseString = responseString;
    }

    /**
     * @param responseString gets printed to the user
     * @param exceptionMessageString gets printed to the error logs page
     */
    public RestException(String responseString, String exceptionMessageString) {
        super(exceptionMessageString);
        this.responseString = responseString;
    }

    /**
     * @param e the wrapped exception
     * @param responseString gets printed to the user
     * @param exceptionMessageString gets printed to the error logs page
     */
    public RestException(Exception e, String responseString, String exceptionMessageString) {
        super(exceptionMessageString, e);
        this.responseString = responseString;
    }

    public String getResponseString() {
        return responseString;
    }

}
