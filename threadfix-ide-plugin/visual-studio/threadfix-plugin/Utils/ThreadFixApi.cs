﻿////////////////////////////////////////////////////////////////////////
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
        private static readonly string RootElement = "object";
        private static readonly string ApiKeyParameter = "apiKey";
        private static readonly string InvalidUrlMessage = "Please provide a valid ThreadFix url in the options menu.";
        private static readonly string InvalidKeyMessgae = "Please provide a valid ThreadFix api key in the options menu.";

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

            request.AddParameter("AppId", appId, ParameterType.UrlSegment);

            return Execute<List<VulnerabilityMarker>>(request);
        }

        public T Execute<T>(RestRequest request) where T : new()
        {
            if (!ValidUrl(_threadFixPlugin.Options.ApiUrl))
            {
                throw new ApplicationException(InvalidUrlMessage);
            }

            if (string.IsNullOrEmpty(_threadFixPlugin.Options.ApiKey))
            {
                throw new ApplicationException(InvalidKeyMessgae);
            }

            var client = new RestClient();
            client.BaseUrl = new Uri(_threadFixPlugin.Options.ApiUrl);

            request.AddParameter(ApiKeyParameter, _threadFixPlugin.Options.ApiKey);
            request.RequestFormat = DataFormat.Json;
            request.RootElement = RootElement;

            var response = client.Execute<T>(request);
            if (response.ErrorException != null)
            {
                throw new ApplicationException(response.ErrorException.InnerException.Message, response.ErrorException);
            }

            // TODO: Serialize the entire response intead of just "object" and check for errors sent back from threadfix api

            return response.Data;
        }

        private bool ValidUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return false;
            }

            Uri result;
            return Uri.TryCreate(url, UriKind.Absolute, out result) && (result.Scheme == Uri.UriSchemeHttp || result.Scheme == Uri.UriSchemeHttps);
        }
    }
}