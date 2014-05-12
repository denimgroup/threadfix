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
    updater.updateParameters = function($scope) {
        $scope.parameters.genericSeverities = [];
        if ($scope.parameters.severities.info) {
            $scope.parameters.genericSeverities.push({ intValue: 1 });
        }
        if ($scope.parameters.severities.low) {
            $scope.parameters.genericSeverities.push({ intValue: 2 });
        }
        if ($scope.parameters.severities.medium) {
            $scope.parameters.genericSeverities.push({ intValue: 3 });
        }
        if ($scope.parameters.severities.high) {
            $scope.parameters.genericSeverities.push({ intValue: 4 });
        }
        if ($scope.parameters.severities.critical) {
            $scope.parameters.genericSeverities.push({ intValue: 5 });
        }

        $scope.parameters.teams.forEach(function(filteredTeam) {
            filteredTeam.id = undefined;
        });
        $scope.teams.forEach(function(team) {
            $scope.parameters.teams.forEach(function(filteredTeam) {
                if (team.name === filteredTeam.name) {
                    filteredTeam.id = team.id;
                }
            });
        });

        // This may be a problem down the road, but it's easier than fighting angular / bootstrap typeahead
        $scope.parameters.applications.forEach(function(filteredApp) {
            filteredApp.id = undefined;
        });
        $scope.applications.forEach(function(app) {
            $scope.parameters.applications.forEach(function(filteredApp) {
                if (filteredApp.name === (app.team.name + " / " + app.name)) {
                    filteredApp.id = app.id;
                }
            });
        });

        $scope.parameters.channelTypes = $scope.parameters.scanners;

        $scope.parameters.channelTypes.forEach(function(filteredScanner) {
            filteredScanner.id = undefined;
        });
        $scope.scanners.forEach(function(scanner) {
            $scope.parameters.channelTypes.forEach(function(filteredScanner) {
                if (scanner.name === filteredScanner.name) {
                    filteredScanner.id = scanner.id;
                }
            });
        });

        var numberRegex = /^([0-9]+)$/;
        var autocompleteRegex = /.* ([0-9]+)\)$/;

        $scope.parameters.genericVulnerabilities.forEach(function(genericVulnerability) {
            if (numberRegex.test(genericVulnerability.text)) {
                genericVulnerability.id = numberRegex;
            } else if (autocompleteRegex.test(genericVulnerability.text)) {
                var matches = autocompleteRegex.exec(genericVulnerability.text);
                genericVulnerability.id = matches[1];
            } else {
                genericVulnerability.id = undefined;
            }
        });

        $scope.parameters.endDate = undefined;
        $scope.parameters.startDate = undefined;

        var date;

        if ($scope.endDate) {
            date = new Date($scope.endDate);
            if (date) {
                $scope.parameters.endDate = date.getTime();
            }
        }
        if ($scope.startDate) {
            date = new Date($scope.startDate)
            if (date) {
                $scope.parameters.startDate = date.getTime();
            }
        }
    }

    return updater;
});