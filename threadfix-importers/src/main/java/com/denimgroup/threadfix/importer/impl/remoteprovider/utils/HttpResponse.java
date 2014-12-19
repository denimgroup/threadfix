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
package com.denimgroup.threadfix.importer.impl.remoteprovider.utils;

import com.denimgroup.threadfix.exception.RestIOException;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;

/**
 * Created by mac on 6/2/14.
 */
public class HttpResponse {

    private final int status;
    private final InputStream inputStream;

    private HttpResponse(int status, InputStream inputStream) {
        assert status > -2;
        assert status < 1000;

        this.status = status;
        this.inputStream = inputStream;
    }

    public static HttpResponse success(int status, InputStream inputStream) {
        assert status == 200;

        return new HttpResponse(status, inputStream);
    }

    public static HttpResponse failure(int status) {
        return new HttpResponse(status, null);
    }

    public static HttpResponse failure(int status, InputStream stream) {
        return new HttpResponse(status, stream);
    }

    public static HttpResponse failure() {
        return new HttpResponse(-1, null);
    }

    public boolean isValid() {
        return status == 200 && inputStream != null;
    }

    public int getStatus() {
        return status;
    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public String getBodyAsString() {
        try {
            return IOUtils.toString(getInputStream());
        } catch (IOException e) {
            throw new RestIOException(e, "Got IOException while trying to read a string from an inputstream.");
        }
    }

    public String getStringOrThrowRestException() {
        if (isValid()) {
            try {
                return IOUtils.toString(getInputStream());
            } catch (IOException e) {
                throw new RestIOException(e, "Got IOException while trying to read a string from an inputstream.");
            }
        } else {
            throw new RestIOException("Got bad response from server: " + getStatus(), getStatus());
        }
    }
}
