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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import org.junit.Test;

import java.io.File;
import java.util.List;
import java.util.Set;

/**
 * Created by mac on 9/4/14.
 */
public class WebFormsEndpointGeneratorTests {

    @Test
    public void testBasic() {
        EndpointGenerator endpointGenerator = WebFormsEndpointGenerator.getGenerator(new File(TestConstants.WEB_FORMS_SAMPLE));

        List<Endpoint> endpoints = endpointGenerator.generateEndpoints();
        assert !endpoints.isEmpty() : "Got empty endpoints for " + TestConstants.WEB_FORMS_SAMPLE;

        Set<String> parameters = endpoints.get(0).getParameters();
        assert parameters.contains("newitem") :
            "Parameters didn't contain newitem: " + parameters;

    }

}
