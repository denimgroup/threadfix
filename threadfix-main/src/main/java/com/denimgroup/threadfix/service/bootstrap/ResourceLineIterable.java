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
package com.denimgroup.threadfix.service.bootstrap;

import org.springframework.beans.factory.annotation.Autowired;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Iterator;

/**
 * Created by mcollins on 8/13/15.
 */
public class ResourceLineIterable implements Iterable<String> {

    final BufferedReader reader;

    private ResourceLineIterable(BufferedReader reader) {
        this.reader = reader;
    }

    public static ResourceLineIterable getIterator(String name) {
        InputStream stream = ScannerTypeBootstrapper.class
                .getClassLoader()
                .getResourceAsStream(name);

        if (stream == null) {
            throw new IllegalStateException(name + " wasn't found.");
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(stream));

        return new ResourceLineIterable(reader);
    }

    @Override
    public Iterator<String> iterator() {
        return new Iterator<String>() {
            String next    = null;
            boolean initialized = false;

            private void initialize() {
                incrementNext();
                initialized = true;
            }

            private void incrementNext() {
                try {
                    next = reader.readLine();
                } catch (IOException e) {
                    throw new IllegalStateException("Unable to get next line.", e);
                }
            }

            @Override
            public boolean hasNext() {
                if (!initialized) {
                    initialize();
                }

                return next != null;
            }

            @Autowired
            public void remove() {
                throw new UnsupportedOperationException();
            }

            @Override
            public String next() {

                if (!initialized) {
                    initialize();
                }

                if (next == null) {
                    throw new IllegalStateException("Next called with no next element");
                }

                String current = next;
                incrementNext();
                return current;
            }
        };
    }
}
