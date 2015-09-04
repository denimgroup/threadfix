
// this file just declares the module and its dependencies


// the httpProvider stuff configures things to work like x-www-form-urlencoded
var threadfixModule = angular.module('threadfix', ['ui.bootstrap', 'angularFileUpload', 'threadfixFilters', 'd3', 'dynform', 'ngSanitize']);

threadfixModule.run(function($http, tfEncoder) {
    // Use x-www-form-urlencoded Content-Type
    $http.defaults.headers.post['Content-Type'] = 'application/x-www-form-urlencoded;charset=utf-8';

    $http.defaults.transformResponse.push(function(data) {
        if (/<div ng\-controller="LoginController">/.exec(data)) {
            if (/<div id="loginError" class="sessionTimeout"/.exec(data)) {
                window.location.pathname = tfEncoder.encode('/login.jsp?sessionTimeout=true', true);
            } else if (/<div id="loginError" class="concurrentSessions"/.exec(data)) {
                window.location.pathname = tfEncoder.encode('/login.jsp?concurrentSessions=true', true);
            } else {
                // this self-assignment makes the page reload, forcing a redirect to login.jsp
                window.location.pathname = window.location.pathname;
            }
        }

        return data;
    });

    $http.defaults.transformResponse.push(function (data, headerGetter) {
        if (data === "") {
            return {
                "message": "Please refresh the page (CSRF error.)",
                "success": false,
                "responseCode": 204
            };
        } else {
            return data;
        }
    });

    // Override $http service's default transformRequest
    $http.defaults.transformRequest = [function(data)
    {
        /**
         * The workhorse; converts an object to x-www-form-urlencoded serialization.
         * @param {Object} obj
         * @return {String}
         */
        var param = function(obj)
        {
            var query = '';
            var name, value, fullSubName, subName, subValue, innerObj, i;

            for(name in obj)
            {
                value = obj[name];

                if(value instanceof Array)
                {
                    for(i=0; i<value.length; ++i)
                    {
                        subValue = value[i];
                        fullSubName = name + '[' + i + ']';
                        innerObj = {};
                        innerObj[fullSubName] = subValue;
                        query += param(innerObj) + '&';
                    }
                }
                else if(value instanceof Object)
                {
                    for(subName in value)
                    {
                        subValue = value[subName];
                        fullSubName = name + '.' + subName;
                        innerObj = {};
                        innerObj[fullSubName] = subValue;
                        query += param(innerObj) + '&';
                    }
                }
                else if(value !== undefined && value !== null)
                {
                    query += encodeURIComponent(name) + '=' + encodeURIComponent(value) + '&';
                }
            }

            return query.length ? query.substr(0, query.length - 1) : query;
        };

        return angular.isObject(data) && String(data) !== '[object File]' ? param(data) : data;
    }];
});
