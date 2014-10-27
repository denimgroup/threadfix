var myAppModule = angular.module('threadfix')

myAppModule.controller('ReportPageController', function ($scope, $window, $http, tfEncoder, threadfixAPIService, vulnSearchParameterService) {

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.base = window.location.pathname;

    $scope.trendingActive = false;
    $scope.comparisonActive = false;
    $scope.snapshotActive = false;

    $scope.formatId = 1;

    $scope.getReportParameters = function() {
        return {
            organizationId: $scope.teamId,
            applicationId: $scope.applicationId,
            reportId: $scope.reportId,
            formatId: $scope.formatId
        };
    };

//    $scope.loading = true;

    var loadReport = function() {
        if ($scope.initialized) {
//            $scope.loading = true;
//            $http.post(tfEncoder.encode(url), $scope.getReportParameters()).
//                success(function(data, status, headers, config) {
//
//                    $scope.loading = false;
//
//                    if ($scope.firstReportId) {
//                        $scope.reportId = parseInt($scope.firstReportId);
//                        $scope.firstReportId = undefined;
//                    }
//                }).
//                error(function(data, status, headers, config) {
//
//                    // TODO improve error handling and pass something back to the users
//                    $scope.leftReportFailed = true;
//                    $scope.loadingLeft = false;
//                    $scope.loading = false;
//                });
        }
    };

    $scope.loadReport = function() { loadReport(); }

    $scope.updateApplications = function() {
        var teamIdInt = parseInt($scope.teamId);

        if (teamIdInt === -1) {
            $scope.application = {id: -1, name: "All"};
            $scope.applications = undefined;
        } else {

            $scope.teams.forEach(function(team) {
                if (team.id === teamIdInt) {
                    $scope.team = team;
                }
            });

            $scope.applications = $scope.team.applications;
            if ($scope.applications && $scope.applications[0].id !== -1) {
                $scope.applications.unshift({id: -1, name: "All"});
            }
            $scope.application = $scope.applications[0];
        }

        loadReport();
    };


    $scope.$on('rootScopeInitialized', function() {
        threadfixAPIService.getVulnSearchParameters().
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.teams = data.object.teams;
                    $scope.scanners = data.object.scanners;
                    $scope.genericVulnerabilities = data.object.vulnTypes;
                    $scope.savedFilters = data.object.savedFilters;
                    $scope.searchApplications = data.object.applications;
                    $scope.filterParameters = data.object.filterParameters;

                    $scope.teams.sort(nameCompare)

                    $scope.teamId = -1;
                    $scope.applicationId = -1;
                    $scope.team = $scope.teams[0];
                    $scope.applications = undefined;

//                    if ($scope.firstTeamId) {
//                        $scope.teamId = parseInt($scope.firstTeamId);
//                        $scope.teams.forEach(function(team) {
//                            if (team.id === $scope.teamId) {
//                                $scope.team = team;
//                            }
//                        });
//
//                        if ($scope.firstAppId) {
//                            $scope.applicationId = parseInt($scope.firstAppId);
//                        }
//                    }

                    $scope.initialized = true;

                    if ($scope.firstReportId) {
                        $scope.reportId = parseInt($scope.firstReportId);
//                        $scope.$broadcast('loadTrendingReport');
                    } else {
                        $scope.reportId = 1;
                    }

                    if ($scope.filterParameters) {
                        $scope.vulnSearch = true;
                        $scope.loading = false;
                        $scope.$broadcast('loadVulnerabilitySearchTable');
                    } else {
                        $scope.$broadcast('loadTrendingReport');
//                        loadReport();
                    }

                } else {
                    $scope.output = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.loadVulnSearch = function() {
        $scope.vulnSearch = true;
        $scope.trendingActive = false;
        $scope.snapshotActive = false;
        $scope.comparisonActive = false;
        $scope.filterParameters = undefined;
        $scope.$broadcast('loadVulnerabilitySearchTable');
    }

    $scope.loadTrending = function() {

        $scope.trendingActive = true;
        $scope.snapshotActive = false;
        $scope.comparisonActive = false;
        $scope.vulnSearch = false;
        $scope.$broadcast('loadTrendingReport');

    }

    $scope.loadSnapshot = function() {
        $scope.trendingActive = false;
        $scope.snapshotActive = true;
        $scope.comparisonActive = false;
        $scope.vulnSearch = false;
        $scope.$broadcast('loadSnapshotReport');

    }

    $scope.setSortNumber = function(list, attr) {
        $scope.index = attr;
        $scope.reverse = !$scope.reverse;

        list.sort(function(a, b) {
            return ($scope.reverse ? b[attr] - a[attr] : a[attr] - b[attr]);
        });
    }

    $scope.setSortText = function(list, attr) {
        $scope.index = attr;
        $scope.reverse = !$scope.reverse;

        list.sort(function(a, b) {
            return ($scope.reverse ? b[attr].localeCompare(a[attr]) : a[attr].localeCompare(b[attr]));
        });
    }

});