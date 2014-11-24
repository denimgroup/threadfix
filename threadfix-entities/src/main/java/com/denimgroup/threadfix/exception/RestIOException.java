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
 * Created by mac on 7/7/14.
 */
public class RestIOException extends RestException {

    public int getStatusCode() {
        return statusCode;
    }

    int statusCode = -1;

    public RestIOException(String responseString, int statusCode) {
        super(responseString);
        this.statusCode = statusCode;
    }

    public RestIOException(Throwable cause, String responseString) {
        super(cause, responseString);
    }

    public RestIOException(Exception e, String responseString, String exceptionMessageString) {
        super(e, responseString, exceptionMessageString);
    }

    public RestIOException(Throwable cause, String responseString, int statusCode) {
        super(cause, responseString);
        this.statusCode = statusCode;
    }

    public RestIOException(Exception e, String responseString, String exceptionMessageString, int statusCode) {
        super(e, responseString, exceptionMessageString);
        this.statusCode = statusCode;
    }
}
