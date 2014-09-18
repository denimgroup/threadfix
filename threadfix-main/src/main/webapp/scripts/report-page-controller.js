var myAppModule = angular.module('threadfix')

myAppModule.controller('ReportPageController', function ($scope, $window, $http, tfEncoder, threadfixAPIService, vulnSearchParameterService) {

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.base = window.location.pathname;

    $scope.trendingActive = false;
    $scope.comparisonActive = false;

    $scope.tabs = [
        {
            title: "Trending",
            active: true,
            options: [
                { name: "Trending Scans", id: 1 },
                { name: "Monthly Progress", id: 7 },
                { name: "Vulnerability Trending", id: 9 }
            ]
        },
        {
            title: "Snapshot",
            options: [
                { name: "Point in Time", id: 2 },
                { name: "Progress By Vulnerability", id: 3 },
                { name: "Portfolio Report", id: 8 },
                { name: "Most Vulnerable Applications", id: 10 },
                { name: "Vulnerability List", id: 11 }
            ]
        },
        {
            title: "Comparison",
            options: [
                { name: "Scan Comparison By Vulnerability", id: 4 },
                { name: "Scan Comparison Summary", id: 5 },
                { name: "Scan Comparison Detail", id: 6 }
            ]
        }
    ];

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
            if ($scope.applications[0].id !== -1) {
                $scope.applications.unshift({id: -1, name: "All"});
            }
            $scope.application = $scope.applications[0];
        }

        loadReport();
    }

    $scope.clearApplications = function() {
        $scope.applications = undefined;
    }

    $scope.applications = undefined;
    $scope.options = $scope.tabs[0].options;

    $scope.formatId = 1;

    $scope.getReportParameters = function() {
        return {
            organizationId: $scope.teamId,
            applicationId: $scope.applicationId,
            reportId: $scope.reportId,
            formatId: $scope.formatId
        };
    };

    $scope.loading = true;

    var loadReport = function() {
        if ($scope.initialized) {
            $scope.loading = true;
            var url = "/reports/ajax";
            if ($scope.reportId === '6' || $scope.reportId === '11' ) {
                url = "/reports/ajax/page";
            }
            $http.post(tfEncoder.encode(url), $scope.getReportParameters()).
                success(function(data, status, headers, config) {

                    $scope.reportHTML = undefined;
                    $scope.loading = false;

                    if ($scope.reportId === '6') {
                        $scope.headerList = data.object.headerList;
                        $scope.listOfLists = data.object.listOfLists;
                        $scope.columnCount = data.object.columnCount;

                    } else if ($scope.reportId === '11') {
                        $scope.severityMap = {};
                        $scope.severityMap["Critical"] = 4;
                        $scope.severityMap["High"] = 3;
                        $scope.severityMap["Medium"] = 2;
                        $scope.severityMap["Low"] = 1;
                        $scope.severityMap["Info"] = 0;
                        $scope.listOfLists = data.object.listOfLists;
                    } else {
                        $scope.reportHTML = data;
                    }

                    if ($scope.firstReportId) {
                        $scope.reportId = parseInt($scope.firstReportId);
                        $scope.firstReportId = undefined;
                    }
                }).
                error(function(data, status, headers, config) {

                    // TODO improve error handling and pass something back to the users
                    $scope.leftReportFailed = true;
                    $scope.loadingLeft = false;
                    $scope.loading = false;
                });
        }
    };

    $scope.loadReport = function() { loadReport(); }

    $scope.updateOptions = function(tab) {
        $scope.trendingActive = false;
        $scope.vulnSearch = false;
        $scope.comparisonActive = false;
        $scope.options = tab.options;
        $scope.reportId = tab.options[0].id;

        loadReport();
    }

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

                    $scope.teams.unshift({id: -1, name: "All"});
                    $scope.teamId = -1;
                    $scope.applicationId = -1;
                    $scope.team = $scope.teams[0];
                    $scope.application = {id: -1, name: "All"};
                    $scope.applications = undefined;

                    if ($scope.firstTeamId) {
                        $scope.teamId = parseInt($scope.firstTeamId);
                        $scope.teams.forEach(function(team) {
                            if (team.id === $scope.teamId) {
                                $scope.team = team;
                            }
                        });

                        if ($scope.firstAppId) {
                            $scope.applications = $scope.team.applications;
                            if ($scope.applications[0].id !== -1) {
                                $scope.applications.unshift({id: -1, name: "All"});
                            }

                            $scope.applicationId = parseInt($scope.firstAppId);

                            if (!$scope.application) {
                                $scope.application = $scope.applications[0];
                            }
                        }
                    }

                    $scope.initialized = true;

                    if ($scope.firstReportId) {
                        $scope.reportId = parseInt($scope.firstReportId);
                    } else {
                        $scope.reportId = 1;
                    }

                    if ($scope.filterParameters) {
                        $scope.vulnSearch = true;
                        $scope.loading = false;
                        $scope.$broadcast('loadVulnerabilitySearchTable');
                    } else {
                        loadReport();
                    }

                } else {
                    $scope.output = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.triggerCSVDownload = function() {
        $scope.formatId = 2;
        loadReport();
        $scope.formatId = 1;
    }

    $scope.triggerPDFDownload = function() {
        $scope.formatId = 3;
        loadReport();
        $scope.formatId = 1;
    }

    $scope.setSort = function(index) {
        $scope.index = index;
        $scope.reverse = !$scope.reverse;

        // Sorting for Vulnerability List
        if ($scope.reportId === '11') {
            if (index === 0) {
                // Sorting CWEID
                return sortID();
            } else if (index === 4) {
                // Sorting Severity
                return sortSeverity();
            }
        }

        $scope.listOfLists.sort(function(a, b) {
            if ($scope.reverse) {
                if (a[index] > b[index]) return 1;
                if (a[index] < b[index]) return -1;
                return 0;
            } else {
                if (a[index] < b[index]) return 1;
                if (a[index] > b[index]) return -1;
                return 0;
            }
        });
    }

    var sortID = function() {
        $scope.listOfLists.sort(function(a, b) {
            var intA = Number(a[0]);
            var intB = Number(b[0]);
            if ($scope.reverse) {
                if (intA > intB) return 1;
                if (intA < intB) return -1;
                return 0;
            } else {
                if (intA < intB) return 1;
                if (intA > intB) return -1;
                return 0;
            }
        });
    }

    var sortSeverity = function() {
        $scope.listOfLists.sort(function(a, b) {
            if ($scope.reverse) {
                if ($scope.severityMap[a[4]] > $scope.severityMap[b[4]]) return 1;
                if ($scope.severityMap[a[4]] < $scope.severityMap[b[4]]) return -1;
                return 0;
            } else {
                if (($scope.severityMap[a[4]] < $scope.severityMap[b[4]])) return 1;
                if (($scope.severityMap[a[4]] > $scope.severityMap[b[4]])) return -1;
                return 0;
            }
        });
    }

    $scope.loadVulnSearch = function() {
        $scope.vulnSearch = true;
        $scope.trendingActive = false;
        $scope.comparisonActive = false;
        $scope.filterParameters = undefined;
        $scope.$broadcast('loadVulnerabilitySearchTable');
    }

    $scope.loadTrending = function() {

        $scope.trendingActive = true;
        $scope.comparisonActive = false;
        $scope.vulnSearch = false;
        $scope.tabs.forEach(function(tab) {
            tab.active = false;
        });
        $scope.$broadcast('loadTrendingReport');

    }

    $scope.loadComparison = function() {

        $scope.trendingActive = false;
        $scope.comparisonActive = true;
        $scope.vulnSearch = false;
        $scope.tabs.forEach(function(tab) {
            tab.active = false;
        });
        $scope.$broadcast('loadComparisonReport');

    }

});