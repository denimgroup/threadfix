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
package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.DefaultRequestConfigurer;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 3/2/15.
 */
@RemoteProvider(name = "Sample Remote Provider")
public class SampleRemoteProvider extends AbstractRemoteProvider {

    // You must have a 0-arg constructor
    public SampleRemoteProvider() {
        super("Sample Remote Provider");
    }

    /**
     * This method is where the remote calls are made and parsed into ThreadFix data types
     * @param remoteProviderApplication configured information
     * @return list of scans from remote source
     */
    @Override
    public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {

        // There is authentication information available in remoteProviderApplication

        remoteProviderApplication.getNativeId(); // should contain the identifying ID

        // this field contains the user's configuration
        RemoteProviderType type = remoteProviderType;

        // default username / password
        String username = type.getUsername();
        String password = type.getPassword();

        // default api key
        String apiKey = type.getApiKey();

        // arbitrary fields, configure these in the csv file at src/main/resources/custom/sample.csv
        List<RemoteProviderAuthenticationField> fields = type.getAuthenticationFields();

        type.getAuthenticationFieldValue("Sample field"); // for example, can be anything

        // You can use the HTTP utils like so (or use other HTTP libraries of course):
        RemoteProviderHttpUtils utils = new RemoteProviderHttpUtilsImpl<>(SampleRemoteProvider.class);

        // configure request
        DefaultRequestConfigurer configurer = new DefaultRequestConfigurer();

        configurer.withContentType("application/xml") // content type header sugar
                .withHeaders(new String[]{"header 1", "header 2"}, new String[]{"value 1", "value 2"}) // add headers
                .withUsernamePassword("my username", "my password") // does basic authentication
                .withPostParameters(new String[] { "param1", "param2"}, new String[] { "value1", "value2" }) // normal post params
                .withRequestBody("{json: body}", "application/json");

//        utils.getUrlWithConfigurer("http://my.configured.url/webendpoint", configurer);

        // alternatively, execute arbitrary Java on the request before it goes out.
//        utils.postUrlWithConfigurer("http://my.configured.url/webendpoint", new RequestConfigurer() {
//            @Override
//            public void configure(HttpMethodBase method) {
//                // interact with HttpMethodBase here
//            }
//        });

        Scan scan = new Scan();

        // for more information about populating the Scan object, please see the sample scan importer implementation (SampleImporter)

        Map<FindingKey, String> findingMap = map(
                FindingKey.VULN_CODE, "XSS",
                FindingKey.PARAMETER, "username",
                FindingKey.PATH, "/login.jsp",
                FindingKey.SEVERITY_CODE, "High",
                FindingKey.NATIVE_ID, "myId" // this is necessary
        );

        Finding finding = constructFinding(findingMap);

        scan.setFindings(list(finding));

        return list(scan);
    }

    @Override
    public List<RemoteProviderApplication> fetchApplications() {

        // remoteProviderType.getAuthenticationFieldValue("url"); // same data is available in here as in getScans()
        // you can also use the same RemoteProviderHttpUtils class

        // here you need to create instances of the RemoteProviderApplication class and populate meaningful values
        RemoteProviderApplication newApplication = new RemoteProviderApplication();

        // these are the fields you need to supply
        newApplication.setNativeId("my-id");
        newApplication.setNativeName("Human Name from server");

        List<RemoteProviderApplication> applications = list();

        applications.add(newApplication);

        return applications;
    }
}
