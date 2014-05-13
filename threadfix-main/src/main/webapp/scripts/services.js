var threadfixModule = angular.module('threadfix')

threadfixModule.factory('tfEncoder', function($rootScope, $location) {

    var tfEncoder = {};

    tfEncoder.encode = function(path) {
        return $rootScope.urlRoot + path + $rootScope.csrfToken;
    }

    tfEncoder.encodeRelative = function(path) {
        return $location.path() + path + $rootScope.csrfToken;
    }

    tfEncoder.urlRoot = $rootScope.urlRoot;

    return tfEncoder;
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
    }

    return threadfixAPIService;
});

threadfixModule.factory('threadFixModalService', function($http) {

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
        if (parameters.severities.info) {
            parameters.genericSeverities.push({ intValue: 1 });
        }
        if (parameters.severities.low) {
            parameters.genericSeverities.push({ intValue: 2 });
        }
        if (parameters.severities.medium) {
            parameters.genericSeverities.push({ intValue: 3 });
        }
        if (parameters.severities.high) {
            parameters.genericSeverities.push({ intValue: 4 });
        }
        if (parameters.severities.critical) {
            parameters.genericSeverities.push({ intValue: 5 });
        }

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

        // This may be a problem down the road, but it's easier than fighting angular / bootstrap typeahead
        parameters.applications.forEach(function(filteredApp) {
            filteredApp.id = undefined;
        });
        $scope.applications.forEach(function(app) {
            parameters.applications.forEach(function(filteredApp) {
                if (filteredApp.name === (app.team.name + " / " + app.name)) {
                    filteredApp.id = app.id;
                }
            });
        });

        parameters.channelTypes = parameters.scanners;

        parameters.channelTypes.forEach(function(filteredScanner) {
            filteredScanner.id = undefined;
        });
        $scope.scanners.forEach(function(scanner) {
            parameters.channelTypes.forEach(function(filteredScanner) {
                if (scanner.name === filteredScanner.name) {
                    filteredScanner.id = scanner.id;
                }
            });
        });

        var numberRegex = /^([0-9]+)$/;
        var autocompleteRegex = /.* ([0-9]+)\)$/;

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

        parameters.endDate = undefined;
        parameters.startDate = undefined;

        var date;

        if ($scope.endDate) {
            date = new Date($scope.endDate);
            if (date) {
                parameters.endDate = date.getTime();
            }
        }
        if ($scope.startDate) {
            date = new Date($scope.startDate)
            if (date) {
                parameters.startDate = date.getTime();
            }
        }
    }

    updater.serialize = function($scope, parameters) {

        var myParameters = angular.copy(parameters)

        updater.updateParameters($scope, myParameters);

        return {
            json: JSON.stringify(myParameters)
        };
    }

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
    }

    transformer.transform = function(serverResponse) {
        var initialCategories = [getCategory('Critical', 5), getCategory('High', 4), getCategory('Medium', 3), getCategory('Low', 2), getCategory('Info', 1)];

        serverResponse.forEach(function(element) {
            var newTreeCategory = initialCategories[5 - element.intValue]; // use the int value backwards to get the index
            newTreeCategory.total = newTreeCategory.total + element.numResults;
            newTreeCategory.entries.push(element);
        });

        var newTree = [];

        initialCategories.forEach(function(category) {
            if (category.total > 0) {
                newTree.push(category);
            }
        });

        if (newTree.length === 1) {
            newTree[0].expanded = true;
        }

        return newTree;
    }

    return transformer;
});
