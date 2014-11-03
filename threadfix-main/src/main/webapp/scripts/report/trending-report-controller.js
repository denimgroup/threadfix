var module = angular.module('threadfix');

module.controller('TrendingReportController', function($scope, $rootScope, $window, $http, tfEncoder, reportUtilities, filterService) {

    $scope.parameters = {};
    $scope.filterScans = [];
    $scope.noData = false;
    $scope.margin = [70, 70, 100, 70];
    $scope.savedDefaultTrendingFilter = undefined;

    var startIndex, endIndex;

    $scope.resetFilters = function() {
        if ($scope.savedDefaultTrendingFilter) {
            $scope.selectedFilter = $scope.savedDefaultTrendingFilter;
            $scope.parameters = JSON.parse($scope.savedDefaultTrendingFilter.json);
            if ($scope.parameters.startDate)
                $scope.parameters.startDate = new Date($scope.parameters.startDate);
            if ($scope.parameters.endDate)
                $scope.parameters.endDate = new Date($scope.parameters.endDate);
        } else
            $scope.parameters = {
                teams: [],
                applications: [],
                severities: {},
                showClosed: false,
                showOld: false,
                showHidden: false,
                showTotal: true,
                showNew: true,
                showResurfaced: true,
                daysOldModifier: 'LastYear',
                endDate: undefined,
                startDate: undefined
            };
    };


    $scope.$on('loadTrendingReport', function() {
        $scope.noData = false;
        $scope.savedFilters = $scope.$parent.savedFilters.filter(function(filter){
            var parameters = JSON.parse(filter.json);
            return (parameters.filterType && parameters.filterType.isTrendingFilter);
        });
        filterService.findDefaultFilter($scope);

        if (!$scope.allScans) {
            $scope.loading = true;
            $http.post(tfEncoder.encode("/reports/trendingScans"), $scope.getReportParameters()).
                success(function(data) {
                    $scope.loading = false;
                    $scope.resetFilters();
                    $scope.allScans = data.object.scanList;
                    if ($scope.$parent.teamId !== -1 && $scope.$parent.applicationId === -1) {
                        $scope.parameters.teams = [$scope.$parent.team];
                        $scope.parameters.applications = [];
                        $scope.$broadcast("updateBackParameters", $scope.parameters);
                    }
                    if ($scope.$parent.applicationId !== -1) {
                        var app = angular.copy($scope.$parent.application);
                        app.name = $scope.$parent.team.name + " / " + app.name;
                        $scope.parameters.applications = [app];
                        $scope.parameters.teams = [];
                        $scope.$broadcast("updateBackParameters", $scope.parameters);
                    }
                    if ($scope.allScans) {
                        $scope.allScans.sort(function (a, b) {
                            return a.importTime - b.importTime;
                        });
                       refreshScans();
                    } else {
                        $scope.noData = true;
                    };
                    $rootScope.$broadcast('allTrendingScans', $scope.allScans);
                }).
                error(function() {
                    $scope.loading = false;
                });
        }
        $scope.$parent.trendingActive = true;
    });

    $scope.$on('resetParameters', function(event, parameters) {
        if (!$scope.$parent.trendingActive)
            return;
        $scope.parameters = angular.copy(parameters);
        refreshScans();
    });

    $scope.$on('updateDisplayData', function(event, parameters) {
        if (!$scope.$parent.trendingActive)
            return;
        $scope.parameters = angular.copy(parameters);
        updateDisplayData();
    });

     var refreshScans = function(){
        $scope.loading = true;
        filterByTeamAndApp();
        filterByTime();
        if ($scope.filterScans.length === 0) {
            $scope.noData = true;
        } else {
            $scope.noData = false;
        }
        updateDisplayData();
        $scope.loading = false;
    };

    var updateDisplayData = function(){
        reportUtilities.createTeamAppNames($scope);
        $scope.trendingScansData = [];
        $scope.totalVulnsByChannelMap = {};
        $scope.infoVulnsByChannelMap = {};
        $scope.lowVulnsByChannelMap = {};
        $scope.mediumVulnsByChannelMap = {};
        $scope.highVulnsByChannelMap = {};
        $scope.criticalVulnsByChannelMap = {};
        $scope.filterScans.forEach(function(scan, index){
            var _scan = filterDisplayData(scan);
            if ((!startIndex || startIndex <= index)
                && (!endIndex || endIndex >= index))
                $scope.trendingScansData.push(_scan);
        });
    };

    var filterDisplayData = function(scan) {
        var data = {};
        data.importTime = scan.importTime;
        if ($scope.parameters.showNew)
            data.New = scan.numberNewVulnerabilities;
        if ($scope.parameters.showResurfaced)
            data.Resurfaced = scan.numberResurfacedVulnerabilities;
        if ($scope.parameters.showTotal) {
            data.Total = calculateTotal(scan);
        }
        if ($scope.parameters.showClosed)
            data.Closed = scan.numberClosedVulnerabilities;
        if ($scope.parameters.showOld)
            data.Old = scan.numberOldVulnerabilities;
        if ($scope.parameters.showHidden)
            data.Hidden = scan.numberHiddenVulnerabilities;

        if ($scope.parameters.severities.info) {
            data.Info = calculateInfo(scan);
        }
        if ($scope.parameters.severities.low) {
            data.Low = calculateLow(scan);
        }
        if ($scope.parameters.severities.medium) {
            data.Medium = calculateMedium(scan);
        }
        if ($scope.parameters.severities.high) {
            data.High = calculateHigh(scan);
        }
        if ($scope.parameters.severities.critical) {
            data.Critical = calculateCritical(scan);
        }
        return data;
    }

    var calculateTotal = function(scan) {
        var adjustedTotal = scan.numberTotalVulnerabilities -
            scan.numberOldVulnerabilities +
            scan.numberOldVulnerabilitiesInitiallyFromThisChannel;
        return trendingTotal($scope.totalVulnsByChannelMap, scan, adjustedTotal);
    }

    var calculateInfo = function(scan) {
        return trendingTotal($scope.infoVulnsByChannelMap, scan, scan.numberInfoVulnerabilities);
    }

    var calculateLow = function(scan) {
        return trendingTotal($scope.lowVulnsByChannelMap, scan, scan.numberLowVulnerabilities);
    }

    var calculateMedium = function(scan) {
        return trendingTotal($scope.mediumVulnsByChannelMap, scan, scan.numberMediumVulnerabilities);
    }

    var calculateHigh = function(scan) {
        return trendingTotal($scope.highVulnsByChannelMap, scan, scan.numberHighVulnerabilities);
    }

    var calculateCritical = function(scan) {
        return trendingTotal($scope.criticalVulnsByChannelMap, scan, scan.numberCriticalVulnerabilities);
    }

    var trendingTotal = function(map, scan, newNum) {
        if (scan.applicationChannelId) {
            map[scan.applicationChannelId] = newNum;
        }

        var numTotal = newNum;
        // This code counts in the old vulns from other channels.
        for (var key in map) {
            if (map.hasOwnProperty(key)) {
                if (!scan.applicationChannelId || scan.applicationChannelId != key) {
                    numTotal += map[key];
                }
            }
        }
        return numTotal;
    }

    var filterByTeamAndApp = function() {

        $scope.filterScans = $scope.allScans.filter(function(scan){
            if ($scope.parameters.teams.length === 0 && $scope.parameters.applications.length === 0)
                return true;
            var i;
            for (i=0; i<$scope.parameters.teams.length; i++) {
                if (scan.team.name === $scope.parameters.teams[i].name) {
                    return true;
                }
            }
            for (i=0; i<$scope.parameters.applications.length; i++) {
                if (beginsWith($scope.parameters.applications[i].name, scan.team.name + " / ") &&
                    endsWith($scope.parameters.applications[i].name, " / " + scan.app.name)) {
                    return true;
                }
            }
            return false;
        });

    };

    var filterByTime = function() {
        var startDate, endDate;
        startIndex = undefined; endIndex = undefined;
        if ($scope.parameters.daysOldModifier) {
            endDate = new Date();
            if ($scope.parameters.daysOldModifier === "LastYear") {
                startDate = new Date(endDate.getFullYear(), endDate.getMonth() - 11, 1);
            } else if ($scope.parameters.daysOldModifier === "LastQuarter") {
                startDate = new Date(endDate.getFullYear(), endDate.getMonth() - 2, 1);
            };
        } else {
            if ($scope.parameters.endDate) {
                endDate = $scope.parameters.endDate;
            }
            if ($scope.parameters.startDate) {
                startDate = $scope.parameters.startDate;
            }
        };

        if (!startDate && !endDate)
            return;
        if (!startDate) startIndex = 0;
        if (!endDate ) endIndex = $scope.filterScans.length - 1;

        $scope.filterScans.some(function(scan, index) {
            if (startIndex && endIndex)
                return true;
            if (!startIndex && startDate && startDate.getTime()<=scan.importTime)
                startIndex = index;
            if (!endIndex && endDate && endDate.getTime() < scan.importTime)
                endIndex = index - 1;
        })
    };

    var endsWith = function(str, suffix) {
        return str.indexOf(suffix, str.length - suffix.length) !== -1;
    };

    var beginsWith = function(str, prefix) {
        return str.indexOf(prefix) == 0;
    };

});
