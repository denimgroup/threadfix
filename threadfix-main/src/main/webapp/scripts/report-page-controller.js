var myAppModule = angular.module('threadfix')

myAppModule.controller('ReportPageController', function ($scope, $window, $http, tfEncoder, threadfixAPIService) {

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.base = window.location.pathname;

    $scope.trendingActive = false;
    $scope.complianceActive = false;
    $scope.snapshotActive = false;

    $scope.formatId = 1;

    $scope.getReportParameters = function() {
        return {
            organizationId: -1,
            applicationId: -1,
            reportId: $scope.reportId,
            formatId: $scope.formatId
        };
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
                    $scope.tags = data.object.tags;
                    $scope.enterpriseTags = data.object.enterpriseTags;

                    $scope.teams.sort(nameCompare)

                    $scope.teamId = -1;
                    $scope.applicationId = -1;
                    $scope.team = $scope.teams[0];
                    $scope.applications = undefined;

                    if ($scope.firstTeamId) {
                        $scope.teamId = parseInt($scope.firstTeamId);
                        $scope.teams.forEach(function(team) {
                            if (team.id === $scope.teamId) {
                                $scope.team = team;
                            }
                        });

                        if ($scope.firstAppId) {
                            $scope.applicationId = parseInt($scope.firstAppId);
                            $scope.searchApplications.forEach(function(app) {
                                if (app.id === $scope.applicationId) {
                                    $scope.application = app;
                                }
                            });
                        }
                    }

                    $scope.initialized = true;

                    if ($scope.firstReportId) {
                        $scope.reportId = parseInt($scope.firstReportId);
                        if ($scope.reportId===9)
                            $scope.loadTrending();
                        else {
                            $scope.loading = false;
                            $scope.$broadcast('loadSnapshotReport');
                        }
                    } else if ($scope.filterParameters) {
                        $scope.vulnSearch = true;
                        $scope.loading = false;
                        $scope.$broadcast('loadVulnerabilitySearchTable');
                    } else {
                        $scope.$broadcast('loadTrendingReport');
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
        $scope.complianceActive = false;
        $scope.filterParameters = undefined;
        $scope.remediationEnterpriseActive = false;
        $scope.$broadcast('loadVulnerabilitySearchTable');
    }

    $scope.loadTrending = function() {
        $scope.trendingActive = true;
        $scope.snapshotActive = false;
        $scope.complianceActive = false;
        $scope.vulnSearch = false;
        $scope.remediationEnterpriseActive = false;
        $scope.$broadcast('loadTrendingReport');

    };

    $scope.loadCompliance = function() {
        $scope.trendingActive = false;
        $scope.snapshotActive = false;
        $scope.complianceActive = true;
        $scope.vulnSearch = false;
        $scope.remediationEnterpriseActive = false;
        $scope.$broadcast('loadComplianceReport');

    };

    $scope.loadSnapshot = function() {
        $scope.trendingActive = false;
        $scope.snapshotActive = true;
        $scope.complianceActive = false;
        $scope.vulnSearch = false;
        $scope.remediationEnterpriseActive = false;
        $scope.$broadcast('loadSnapshotReport');

    };

    $scope.loadEnterpriseRemediation = function() {
        $scope.remediationEnterpriseActive = true;
        $scope.trendingActive = false;
        $scope.snapshotActive = false;
        $scope.complianceActive = false;
        $scope.vulnSearch = false;
        $scope.$broadcast('loadComplianceReport');

    };

    $scope.setSortNumber = function(list, attr) {
        $scope.index = attr;
        $scope.reverse = !$scope.reverse;

        list.sort(function(a, b) {
            return ($scope.reverse ? b[attr] - a[attr] : a[attr] - b[attr]);
        });
    };

    $scope.setSortText = function(list, attr) {
        $scope.index = attr;
        $scope.reverse = !$scope.reverse;

        list.sort(function(a, b) {
            return ($scope.reverse ? b[attr].localeCompare(a[attr]) : a[attr].localeCompare(b[attr]));
        });
    };

});