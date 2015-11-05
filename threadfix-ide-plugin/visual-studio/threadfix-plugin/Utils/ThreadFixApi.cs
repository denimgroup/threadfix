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
//     The Initial Developer of the Origin Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
using DenimGroup.threadfix_plugin.Data;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DenimGroup.threadfix_plugin.Utils
{
    public class ThreadFixApi
    {
        private readonly ThreadFixPlugin _threadFixPlugin;
        private static readonly string ApplicationsResource = "code/applications";
        private static readonly string VulnerabilitiesResource = "code/markers/{AppId}";
        private static readonly string ApiKeyParameter = "apiKey";
        private static readonly string ApiIdParameter = "AppId";

        public ThreadFixApi(ThreadFixPlugin threadFixPlugin)
        {
            _threadFixPlugin = threadFixPlugin;
        }

        public List<ApplicationInfo> GetThreadFixApplications()
        {
            var request = new RestRequest()
            {
                Resource = ApplicationsResource
            };

            return Execute<List<ApplicationInfo>>(request);
        }

        public List<VulnerabilityMarker> GetVulnerabilityMarkers(IEnumerable<string> appIds)
        {
            var markers = new List<VulnerabilityMarker>();
            if (appIds == null || appIds.Count() == 0)
            {
                return markers;
            }

            foreach (var id in appIds)
            {
                markers.AddRange(GetVulnerabilityMarkers(id));
            }
            
            return markers;
        }

        public List<VulnerabilityMarker> GetVulnerabilityMarkers(string appId)
        {
            var request = new RestRequest()
            {
                Resource = VulnerabilitiesResource
            };

            request.AddParameter(ApiIdParameter, appId, ParameterType.UrlSegment);

            return Execute<List<VulnerabilityMarker>>(request);
        }

        public T Execute<T>(RestRequest request) where T : new()
        {
            var client = new RestClient();
            client.BaseUrl = new Uri(_threadFixPlugin.Options.ApiUrl);

            request.AddParameter(ApiKeyParameter, _threadFixPlugin.Options.ApiKey);
            request.RequestFormat = DataFormat.Json;

            var response = client.Execute<ThreadFixApiResponse<T>>(request);
            if (response.ErrorException != null || !response.Data.Success)
            {
                // response.ErrorMessage is any error from the http request (invalid ssl certificate)
                // response.Data.Message is any error return from ThreadFixApi (invalid ThreadFix api key)
                var message = response.ErrorException != null ? response.ErrorMessage : response.Data.Message;
                throw new ApplicationException(message);
            }

            return response.Data.Object;
        }
    }
}
