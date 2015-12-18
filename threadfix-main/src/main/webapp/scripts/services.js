var threadfixModule = angular.module('threadfix');

threadfixModule.factory('tfEncoder', function($rootScope, $location) {

    var tfEncoder = {};

    tfEncoder.encode = function(path, omitCsrfToken) {
        var encodedUrl = $rootScope.urlRoot + path;
        if (!omitCsrfToken) {
            encodedUrl = encodedUrl + $rootScope.csrfToken;
        }
        return encodedUrl;
    };

    tfEncoder.encodeRelative = function(path, omitCsrfToken) {
        var encodedUrl = $location.path() + path;
        if (!omitCsrfToken) {
            encodedUrl = encodedUrl + $rootScope.csrfToken;
        }
        return encodedUrl;
    };

    tfEncoder.urlRoot = $rootScope.urlRoot;

    return tfEncoder;
});

/**
 * This service is a little funky. Basically, every generic-severity directive on the page
 * adds a callback to the callbacks array. Then when the controller sets the severities in
 * customSeverityService, the service calls each of the callbacks, which then set the proper
 * text for each element that has the directive. It's better than declaring a bunch of watchers
 * and using $rootScope, which was my first solution.
 *
 * So, for developers: when you need the custom names for severities, be sure to use the
 * generic-severity directive on the element that needs the text (create a div if necessary.)
 * Call setSeverities on this service and Angular will handle the rest.
 */
threadfixModule.factory('customSeverityService', function() {
    var service = {};

    service.callbacks = [];

    service.map = {};

    service.genericSeverities = [];

    service.setSeverities = function(genericSeverities) {
        genericSeverities.forEach(function(severity) {
            service.map[severity.name] = severity.displayName;
        });

        service.genericSeverities = genericSeverities;

        service.callbacks.forEach(function(callback) {
            callback();
        });
    };

    service.addCallback = function(callbackFunction) {
        service.callbacks.push(callbackFunction);
    };

    service.isInitialized = function() {
        return !!service.map['Critical']; // !! should make this a boolean
    };

    service.getCustomSeverity = function(input) {
        return service.map[input] || input;
    };

    service.getGenericSeverities = function() {
        return service.genericSeverities;
    }

    return service;
});

threadfixModule.factory('threadfixAPIService', function($location, $http, tfEncoder, $rootScope) {

    var threadfixAPIService = {};

    threadfixAPIService.getTeams = function() {
        return $http({
            method: 'GET',
            url: tfEncoder.encode('/organizations/jsonList')
        });
    };

    threadfixAPIService.getVulnSearchParameters = function() {
        return $http({
            method: 'GET',
            url: tfEncoder.encode('/reports/parameters')
        });
    };

    threadfixAPIService.loadAppTableReport = function(id) {
        var url = '/organizations/' + id + '/getReport';

        return $http({
            method: 'GET',
            url: tfEncoder.encode(url)
        });
    };

    threadfixAPIService.loadReport = function(url, query) {
        return $http({
            method: 'GET',
            url: tfEncoder.encode(url) + query
        });
    };

    threadfixAPIService.loadVulns = function() {
        return $http({
            method: 'GET',
            url: $location.path() + "/vulns" + $rootScope.csrfToken
        });
    };

    return threadfixAPIService;
});

threadfixModule.factory('threadFixModalService', function($http, $modal, tfEncoder, $log) {

    var threadFixModalService = {};

    threadFixModalService.post = function(url, data) {
        return $http({
            method: 'POST',
            url: url,
            data : data,
            contentType : "application/x-www-form-urlencoded",
            dataType : "text"
        });
    };

    threadFixModalService.deleteElement = function(elementList, element) {
        var index = elementList.indexOf(element);

        if (index > -1) {
            elementList.splice(index, 1);
        }

        if (elementList.length === 0) {
            elementList = undefined;
        }
    };

    threadFixModalService.deleteElements = function(elementList, elements) {
        for (var i = 0; i < elements.length; i++) {
            threadFixModalService.deleteElement(elementList, elements[i]);
        }
    };

    threadFixModalService.addElement = function(elementList, element) {
        if (!elementList) {
            elementList = [];
        }
        elementList.push(element);
    };

    threadFixModalService.showVulnsModal = function(scope, isStay) {
        var modalInstance = $modal.open({
            templateUrl: 'vulnSummaryModal.html',
            controller: 'VulnSummaryModalController',
            resolve: {
                scope: function () {
                    return scope;
                },
                headers: function () {
                    return scope.headers;
                },
                headerColor: function () {
                    return scope.fillColor;
                },
                isStay: function() {
                    return isStay;
                }
            }
        });

        modalInstance.result.then(function () {},
            function () {
                $log.info('Modal dismissed at: ' + new Date());
            });
    };

    return threadFixModalService;
});

threadfixModule.factory('focus', function ($rootScope, $timeout) {
    return function(name) {
        $timeout(function (){
            $rootScope.$broadcast('focusOn', name);
        });
    }
});

threadfixModule.factory('vulnSearchParameterService', function() {

    var updater = {};

    // glue code to make angular and spring play nice
    updater.updateParameters = function($scope, parameters) {
        parameters.genericSeverities = [];
        if (parameters.severities) {
            if (parameters.severities.info) {
                parameters.genericSeverities.push({intValue: 1});
            }
            if (parameters.severities.low) {
                parameters.genericSeverities.push({intValue: 2});
            }
            if (parameters.severities.medium) {
                parameters.genericSeverities.push({intValue: 3});
            }
            if (parameters.severities.high) {
                parameters.genericSeverities.push({intValue: 4});
            }
            if (parameters.severities.critical) {
                parameters.genericSeverities.push({intValue: 5});
            }
        }

        if ($scope.treeTeam) {
            $scope.parameters.teams = [ { id: $scope.treeTeam.id, name: $scope.treeTeam.name } ];
        } else if (parameters.teams && parameters.teams.length > 0) {
            parameters.teams.forEach(function(filteredTeam) {
                filteredTeam.id = undefined;
            });
            $scope.teams.forEach(function(team) {
                parameters.teams.forEach(function(filteredTeam) {
                    if (team.name === filteredTeam.name) {
                        filteredTeam.id = team.id;
                    }
                });
            });
        }

        if ($scope.treeApplication) {
            var name = '';
            if ($scope.treeApplication.team) {
                name = $scope.treeApplication.team.name + " / " + $scope.treeApplication.name;
            }
            $scope.parameters.applications = [
                {
                id: $scope.treeApplication.id,
                name: name
                }
            ];
        } else if (parameters.applications && parameters.applications.length > 0) {
            // This may be a problem down the road, but it's easier than fighting angular / bootstrap typeahead
            //STran 8/14/2014: oh yes, I'm having problem with this right now
            parameters.applications.forEach(function(filteredApp) {
                filteredApp.id = undefined;
            });
            $scope.searchApplications.forEach(function(app) {
                parameters.applications.forEach(function(filteredApp) {
                    if (filteredApp.name === app.name || filteredApp.name === (app.team.name + " / " + app.name)) {
                        filteredApp.id = app.id;

                        // If we're on the teams page, we should remove the teams restriction
                        // because there's an application now.
                        if ($scope.treeTeam) {
                            $scope.parameters.teams = [];
                        }
                    }
                });
            });
        }

        if (parameters.tags) {
            parameters.tags.forEach(function(filteredTag){
                filteredTag.id = undefined;
            });
            if ($scope.tags) {
                $scope.tags.forEach(function(tag){
                    parameters.tags.forEach(function(filteredTag){
                        if (tag.name === filteredTag.name) {
                            filteredTag.id = tag.id;
                        }
                    });
                })
            }
        }

        if (parameters.vulnTags) {
            parameters.vulnTags.forEach(function(filteredTag){
                filteredTag.id = undefined;
            });
            if ($scope.vulnTags) {
                $scope.vulnTags.forEach(function(tag){
                    parameters.vulnTags.forEach(function(filteredTag){
                        if (tag.name === filteredTag.name) {
                            filteredTag.id = tag.id;
                        }
                    });
                })
            }
        }

        parameters.channelTypes = parameters.scanners;

        if (!parameters.channelTypes)
            parameters.channelTypes = [];
        parameters.channelTypes.forEach(function(filteredScanner) {
            filteredScanner.id = undefined;
        });
        if (!$scope.scanners)
            $scope.scanners = [];
        $scope.scanners.forEach(function(scanner) {
            if (parameters.channelTypes)
                parameters.channelTypes.forEach(function(filteredScanner) {
                    if (scanner.name === filteredScanner.name) {
                        filteredScanner.id = scanner.id;
                    }
                });
        });

        var numberRegex = /^([0-9]+)$/;
        var autocompleteRegex = /.* ([0-9]+)\)$/;

        if (!parameters.genericVulnerabilities)
            parameters.genericVulnerabilities = [];
        parameters.genericVulnerabilities.forEach(function(genericVulnerability) {
            if (numberRegex.test(genericVulnerability.name)) {
                genericVulnerability.id = numberRegex;
            } else if (autocompleteRegex.test(genericVulnerability.name)) {
                var matches = autocompleteRegex.exec(genericVulnerability.name);
                genericVulnerability.id = matches[1];
            } else {
                genericVulnerability.id = undefined;
            }
        });

        parameters.usingComponentsWithKnownVulnerabilities = false;

        if (parameters.owasp) {
            parameters.genericVulnerabilities = [];
            parameters.owasp.top10.forEach(function(owaspVuln){
                owaspVuln.members.forEach(function(cweId){
                    parameters.genericVulnerabilities.push({id: cweId});

                    // Query all vulnerabilities of Sonatype and Dependency Check for
                    // OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities
                    if (cweId === 937)
                        parameters.usingComponentsWithKnownVulnerabilities = true;

                });
            });
        }

        if (parameters.isDISASTIG) {
            parameters.genericVulnerabilities = [];
            $scope.DISA_STIG.forEach(function(cat){
                cat.members.forEach(function(stig){
                    stig.cweIds.forEach(function(cweId){
                        parameters.genericVulnerabilities.push({id: cweId});
                    });
                });
            });
        }

        var date;

        if (parameters.endDate) {
            date = new Date(parameters.endDate);
            if (date) {
                parameters.endDate = date.getTime();
            }
        }
        if (parameters.startDate) {
            date = new Date(parameters.startDate);
            if (date) {
                parameters.startDate = date.getTime();
            }
        }
    };


    updater.convertFromSpringToAngular = function($scope, filterParameters) {

        $scope.parameters.severities = {
            info: false,
            low: false,
            medium: false,
            high: false,
            critical: false
        };

        filterParameters.genericSeverities.forEach(function (severity) {
            if (severity.intValue === 1)
                $scope.parameters.severities.info = true;
            if (severity.intValue === 2)
                $scope.parameters.severities.low = true;
            if (severity.intValue === 3)
                $scope.parameters.severities.medium = true;
            if (severity.intValue === 4)
                $scope.parameters.severities.high = true;
            if (severity.intValue === 5)
                $scope.parameters.severities.critical = true;
        });

        filterParameters.teams.forEach(function (team) {
            if ($scope.treeTeam) {
                $scope.treeTeam = { id: team.id };
            } else {
                $scope.parameters.teams.push(team);
            }
        });

        if (!$scope.treeTeam && $scope.treeApplication) {
            filterParameters.applications.forEach(function (application) {
                $scope.treeApplication = { id: application.id }
            });
        } else {
            filterParameters.applications.forEach(function (application) {
                $scope.parameters.applications.push(application);
            });
        }

        filterParameters.tags.forEach(function (tag) {
            $scope.parameters.tags.push(tag);
        });

        filterParameters.vulnTags.forEach(function (tag) {
            $scope.parameters.vulnTags.push(tag);
        });

        $scope.parameters.genericVulnerabilities = filterParameters.genericVulnerabilities;
    };


    updater.createFilterCriteria = function (d, label) {
        var criteria = {};
        criteria.endDate = d.time;
        criteria.parameters = {};
        criteria.parameters.severities = {};

        d.genericSeverities.forEach(function(severity) {
            criteria.parameters.severities[severity.name.toLowerCase()] = (d.severity === severity.name || d.severity === severity.customName);
        });


        if (d.teamId && label.teamId) {
            criteria.treeTeam = {id: d.teamId};
        } else if (d.teamId) {
            criteria.parameters.teams = [{id: d.teamId, name: d.teamName}];
            criteria.teams = [];
        } else {
            criteria.parameters.teams = [];
            criteria.teams = [];
        }
        if (label.teamsList)
            criteria.parameters.teams.push.apply(criteria.parameters.teams, label.teamsList);

        if (d.appId && label.appId) {
            criteria.treeApplication = {id: d.appId};
        } else if (d.appId) {
            criteria.parameters.applications = [{id: d.appId, name: d.teamName + " / " + d.appName}];
            criteria.searchApplications = [];
        } else {
            criteria.parameters.applications = [];
            criteria.searchApplications = [];
        }
        if (label.appsList)
            criteria.parameters.applications.push.apply(criteria.parameters.applications, label.appsList);

        if (d.tagId && label.tagId) {
            criteria.treeTag = {id: d.tagId};
        } else if (d.tagId) {
            criteria.parameters.tags = [{id: d.tagId, name: d.tagName}];
            criteria.searchTags = [];
        } else {
            criteria.parameters.tags = [];
            criteria.searchTags = [];
        }
        if (label.tagsList)
            criteria.parameters.tags.push.apply(criteria.parameters.tags, label.tagsList);

        if (label.vulnTagsList) {
            criteria.parameters.vulnTags = [];
            criteria.parameters.vulnTags.push.apply(criteria.parameters.vulnTags, label.vulnTagsList);
        }

        criteria.parameters.channelTypes = [];
        criteria.parameters.scanners = [];
        criteria.scanners = [];
        criteria.parameters.genericVulnerabilities = [];
        if (d.tip && d.tip.indexOf("CWE") > -1)
            criteria.parameters.genericVulnerabilities = [{name: d.tip}];
        criteria.parameters.showOpen = true;
        criteria.parameters.showClosed = false;
        criteria.parameters.showFalsePositive = false;
        criteria.parameters.showHidden = false;

        criteria.headers = getHeaders(d);
        criteria.fillColor = d.fillColor;

        criteria.parameters.searchAppText = d.searchAppText;

        return criteria;
    };

    var months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

    var getHeaders = function(data) {
        var headers = [];
        if (data.teamId) {
            headers.push("Team: " + data.teamName);
        }
        if (data.appId) {
            headers.push("Application: " + data.appName);
        }
        headers.push(data.tip + ": " + (data.value ? data.value : (data.y1 - data.y0)));
        if (data.time) {
            headers.push(months[data.time.getMonth()] + " " + data.time.getFullYear());
        }
        return headers;
    };

    updater.serialize = function($scope, parameters) {

        var myParameters = angular.copy(parameters);

        updater.updateParameters($scope, myParameters);

        return {
            json: JSON.stringify(myParameters)
        };
    };

    updater.updateVulnCommentTags = function(dbTagsList, vuln) {
        if (!vuln.vulnerabilityComments)
            vuln.vulnerabilityComments = [];
        if (!dbTagsList)
            dbTagsList = [];

        vuln.vulnerabilityComments.forEach(function(comment){
            comment.tagsList = angular.copy(dbTagsList);
            comment.tagsList.forEach(function(dbTag){
                comment.tags.some(function(vulnTag){
                    if (dbTag.id === vulnTag.id) {
                        dbTag.selected = true;
                        return true;
                    }
                })
            })

        })

    };

    return updater;
});

threadfixModule.factory('vulnTreeTransformer', function() {
    var transformer = {};

    var getCategory = function(name, intValue) {
        return {
            total: 0,
            entries: [],
            name: name,
            intValue: intValue
        }
    };

    transformer.transform = function(map, owasp, disaStig) {

        var customNameHash = {};
        map.severities.forEach(function(severity) {
            customNameHash[severity.name] = severity.displayName;
        });
        var serverResponse = map.tree;

        var initialCategories = [];
        var newTree = [];

        // OWASP TOP 10 report
        if (owasp) {

            var vulnSum = {}, vulnList = [];
            serverResponse.forEach(function(element) {
                var oldNum = 0, oldVulns = [], key = element.genericVulnerability.displayId + "_" +element.memberOf;
                if (vulnSum[key]) {
                    oldNum = vulnSum[key].numResults;
                    oldVulns = vulnSum[key].vulns;
                }
                vulnSum[key] = {
                    genericVulnerability: element.genericVulnerability,
                    numResults: oldNum + element.numResults,
                    vulns: oldVulns.concat(element.vulns),
                    memberOf: element.memberOf
                }
            });

            for (var k in vulnSum)
                vulnList.push(vulnSum[k]);

            owasp.top10.forEach(function(owaspVuln){

                var newTreeCategory = getCategory(owaspVuln.name, 5);
                vulnList.forEach(function(element) {
                    if ((owaspVuln.members.indexOf(element.genericVulnerability.displayId) > -1 && !element.memberOf)
                        || (element.memberOf && owaspVuln.members.indexOf(element.memberOf) > -1)) {
                        newTreeCategory.total = newTreeCategory.total + element.numResults;
                        newTreeCategory.entries.push(element);
                    }
                });
                newTreeCategory.entries.sort(function(a, b) {
                    return b.numResults - a.numResults;
                });
                initialCategories.push(newTreeCategory);
            });

            newTree = initialCategories;

        } else if (disaStig) {

            var vulnSum = {}, vulnList = [];
            serverResponse.forEach(function(element) {
                var oldNum = 0, oldVulns = [], key = element.genericVulnerability.displayId + "_" +element.memberOf;
                if (vulnSum[key]) {
                    oldNum = vulnSum[key].numResults;
                    oldVulns = vulnSum[key].vulns;
                }
                vulnSum[key] = {
                    genericVulnerability: element.genericVulnerability,
                    numResults: oldNum + element.numResults,
                    vulns: oldVulns.concat(element.vulns),
                    memberOf: element.memberOf
                }
            });

            for (var k in vulnSum)
                vulnList.push(vulnSum[k]);

            disaStig.forEach(function(disaStigCat){

                var categorylvl = 5;

                if (disaStigCat.id === "CATI") {
                    categorylvl = 5;
                } else if (disaStigCat.id === "CATII") {
                    categorylvl = 3;
                } else if (disaStigCat.id === "CATIII") {
                    categorylvl = 1;
                }

                var newTreeCategory = getCategory(disaStigCat.name, categorylvl);
                vulnList.forEach(function(element) {

                    disaStigCat.members.forEach(function(disaStig) {
                        if (disaStig.cweIds.indexOf(element.genericVulnerability.displayId) > -1
                            || (element.memberOf && disaStig.cweIds.indexOf(element.memberOf) > -1)) {
                            newTreeCategory.total = newTreeCategory.total + element.numResults;
                            element.preText = disaStig.stigId;
                            newTreeCategory.entries.push(element);
                        }
                    });
                });
                newTreeCategory.entries.sort(function(a, b) {
                    return b.numResults - a.numResults;
                });
                initialCategories.push(newTreeCategory);
            });

            newTree = initialCategories;

        } else {
            initialCategories = [
                getCategory(customNameHash['Critical'], 5),
                getCategory(customNameHash['High'], 4),
                getCategory(customNameHash['Medium'], 3),
                getCategory(customNameHash['Low'], 2),
                getCategory(customNameHash['Info'], 1)
            ];

            serverResponse.forEach(function(element) {
                var newTreeCategory = initialCategories[5 - element.intValue]; // use the int value backwards to get the index
                newTreeCategory.total = newTreeCategory.total + element.numResults;
                newTreeCategory.entries.push(element);
            });

            initialCategories.forEach(function(category) {
                if (category.total > 0) {
                    newTree.push(category);
                }
            });
        }

        if (newTree.length === 1) {
            newTree[0].expanded = true;
        }

        return newTree;
    };

    return transformer;
});

threadfixModule.factory('filterService', function(tfEncoder, vulnSearchParameterService, $http, $log) {
    var filter = {};


    filter.saveCurrentFilters = function($scope) {
        $log.info("Saving filters");

        if ($scope.currentFilterNameInput) {

            var matches = $scope.savedFilters.filter(function(filter) {
                return filter.name === $scope.currentFilterNameInput;
            });

            if (matches && matches.length !== 0 && (!$scope.selectedFilter || $scope.selectedFilter.id !== matches[0].id)) {
                $scope.saveFilterErrorMessage = "A filter with that name already exists.";
                $scope.saveFilterSuccessMessage = undefined;
                return;
            }

            $scope.savingFilter = true;

            $scope.startDate = $scope.parameters.startDate;
            $scope.endDate = $scope.parameters.endDate;
            var submissionObject = vulnSearchParameterService.serialize($scope, $scope.parameters);
            var editing = $scope.selectedFilter && $scope.selectedFilter.id;

            submissionObject.name = $scope.currentFilterNameInput;
            if ($scope.parameters.defaultTrending)
                submissionObject.defaultTrending = true;

            if (editing)
                submissionObject.id = $scope.selectedFilter.id;

            $http.post(tfEncoder.encode("/reports/filter/save"), submissionObject).
                success(function(data, status, headers, config) {
                    $log.info("Successfully saved filters.");
                    $scope.savingFilter = false;

                    if (data.success) {
                        $scope.savedFilters = data.object;
                        $scope.$parent.$parent.savedFilters = data.object;

                        $scope.savedFilters.forEach(function(filter) {
                            if (filter.name === $scope.currentFilterNameInput) {
                                $scope.selectedFilter = filter;
                            }
                        });

                        var defaultFilter = filter.findDefaultFilter($scope);
                        $scope.savedDefaultTrendingFilter = defaultFilter;
                        $scope.$parent.savedDefaultTrendingFilter = defaultFilter;

                        if(!$scope.acFilterPage)
                            $scope.currentFilterNameInput = '';

                        if (editing) {
                            $scope.saveFilterSuccessMessage = 'Successfully edited filter ' + submissionObject.name;
                        } else {
                            $scope.saveFilterSuccessMessage = 'Successfully saved filter ' + submissionObject.name;
                        }
                        $scope.saveFilterErrorMessage = undefined;

                    } else {
                        $scope.saveFilterErrorMessage = "Failure. Message was : " + data.message;
                        $scope.saveFilterSuccessMessage = undefined;
                    }

                }).
                error(function(data, status, headers, config) {
                    $log.info("Failed to save filters.");
                    $scope.saveFilterErrorMessage = "Failed to save team. HTTP status was " + status;
                    $scope.saveFilterSuccessMessage = undefined;
                    $scope.savingFilter = false;
                });
        }
    };

    filter.deleteCurrentFilter = function($scope) {
        if ($scope.selectedFilter) {
            $http.post(tfEncoder.encode("/reports/filter/delete/" + $scope.selectedFilter.id)).
                success(function(data, status, headers, config) {
                    $log.info("Successfully deleted filter.");
                    $scope.initialized = true;

                    if (data.success) {
                        $scope.deleteFilterSuccessMessage = "Successfully deleted filter " + $scope.selectedFilter.name;
                        $scope.selectedFilter = undefined;
                        $scope.savedFilters = data.object;
                        $scope.$parent.$parent.savedFilters = data.object;

                        if($scope.acFilterPage)
                            $scope.currentFilterNameInput = '';

                        if ($scope.savedFilters){

                            var defaultFilter = filter.findDefaultFilter($scope);
                            $scope.savedDefaultTrendingFilter = defaultFilter;
                            $scope.$parent.savedDefaultTrendingFilter = defaultFilter;
                        }
                    } else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }

                    $scope.loading = false;
                }).
                error(function(data, status, headers, config) {
                    $log.info("Failed to save filters.");
                    $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                    $scope.loading = false;
                });
        }
    };

    filter.findDefaultFilter = function($scope) {
        var savedDefaultTrendingFilter = undefined;
        $scope.savedFilters.some(function(filter){
            if (filter.defaultTrending) {
                savedDefaultTrendingFilter = filter;
                return true;
            }
        });
        return savedDefaultTrendingFilter;
    };

    return filter;
});

threadfixModule.factory('timeoutService', function(tfEncoder, $timeout) {

    var timeoutService = {};
    var timer;

    timeoutService.timeout = function() {
        timer = $timeout(function() {
            alert('It\'s been 60 seconds. Your request may have timed out.');
        }, 60000);
    };

    timeoutService.cancel = function() {
        $timeout.cancel(timer);
    };

    return timeoutService;
});

threadfixModule.factory('urlIdShortener', function() {

    var urlIdShortener = {};
    var ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var BASE = ALPHABET.length;

    urlIdShortener.encode = function(num) {
        encodingList = [];
        while (num > 0) {
            encodingList.push(ALPHABET.charAt(num % BASE));
            num = num/BASE >> 0;
        }
        return encodingList.reverse().join("")
    };

    return urlIdShortener;
});

threadfixModule.factory('appUsageService', function() {
    var appUsageService = {};

    appUsageService.getUsage = function(object) {
        var message = "Successfully added application " + object.application.name + ".";

        if (object.hasOwnProperty("applicationCount") && object.hasOwnProperty("applicationCount")) {
            message += " Your license allows for " + object.applicationsAllowed + " applications, " +
                object.applicationCount + " have been created.";
            if (object.applicationCount === 1) {
                message = message.replace("have been", "has been");
            }
        }

        return message;
    };

    return appUsageService;
});
