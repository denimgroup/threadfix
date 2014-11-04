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
         if ($scope.filterScans.length === 0) {
             $scope.noData = true;
             return;
         } else {
             $scope.noData = false;
         }
        filterByTime();
        if ($scope.filterScans.length === 0) {
            $scope.noData = true;
            return;
        } else {
            $scope.noData = false;
        }
        updateDisplayData();
        $scope.loading = false;
    };

    var updateDisplayData = function(){
        var hashBefore, hashAfter;
        reportUtilities.createTeamAppNames($scope);
        $scope.trendingScansData = [];
        $scope.totalVulnsByChannelMap = {};
        $scope.infoVulnsByChannelMap = {};
        $scope.lowVulnsByChannelMap = {};
        $scope.mediumVulnsByChannelMap = {};
        $scope.highVulnsByChannelMap = {};
        $scope.criticalVulnsByChannelMap = {};
        if (startIndex && endIndex) {
            $scope.filterScans.forEach(function(scan, index){
                var _scan = filterDisplayData(scan);

                if (startIndex == index + 1)
                    hashBefore = _scan;
                if (index == endIndex + 1)
                    hashAfter = _scan;
                if ((!startIndex || startIndex <= index)
                    && (!endIndex || endIndex >= index))
                    $scope.trendingScansData.push(_scan);

            });


            if ($scope.trendingScansData.length===1 && $scope.trendingStartDate == $scope.trendingEndDate) {
                $scope.trendingEndDate = (new Date()).getTime();
                var time = new Date($scope.trendingScansData[0].importTime);
                $scope.trendingStartDate = (new Date(time.getFullYear(), time.getMonth() - 1, 1)).getTime();
            }
            $scope.trendingScansData.unshift(createStartHash(hashBefore));
            $scope.trendingScansData.push(createEndHash(hashAfter));
        }
    };

    var createStartHash = function(hashBefore) {
        var startHash = {};
        if ($scope.trendingScansData.length===0)
            return startHash;
        var firstHashInList = $scope.trendingScansData[0];

        if (!hashBefore) {
            startHash.importTime=  $scope.trendingStartDate;
            var keys = Object.keys(firstHashInList);
            keys.forEach(function(key){
                if (key != "importTime")
                    startHash[key] = 0;
            });
        } else {
            var rate1 = (firstHashInList.importTime)-(hashBefore.importTime);
            var rate2 = $scope.trendingStartDate-(hashBefore.importTime);
            startHash.importTime=  $scope.trendingStartDate;
            var keys = Object.keys(firstHashInList);
            keys.forEach(function(key){
                if (key != "importTime") {
                    var value = Math.round(hashBefore[key] + (firstHashInList[key] - hashBefore[key]) / rate1 * rate2);
                    startHash[key] = value;
                }
            });
        }
        return startHash;
    }

    var createEndHash = function(hashAfter) {
        var endHash = {};
        if ($scope.trendingScansData.length===0)
            return endHash;
        var lastHashInList = $scope.trendingScansData[$scope.trendingScansData.length-1];

        if (!hashAfter) {
            endHash.importTime=  $scope.trendingEndDate;
            var keys = Object.keys(lastHashInList);
            keys.forEach(function(key){
                if (key != "importTime")
                    endHash[key] = lastHashInList[key];
            });
        } else {
            var rate1 = (hashAfter.importTime)-(lastHashInList.importTime);
            var rate2 = $scope.trendingEndDate-(hashAfter.importTime);
            endHash.importTime=  $scope.trendingEndDate;
            var keys = Object.keys(lastHashInList);
            keys.forEach(function(key){
                if (key != "importTime") {
                    var value = Math.round(lastHashInList[key] + (hashAfter[key] - lastHashInList[key]) / rate1 * rate2);
                    endHash[key] = value;
                }
            });
        }
        return endHash;
    }

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
        $scope.trendingStartDate = undefined;
        $scope.trendingEndDate = undefined;
        startIndex = undefined; endIndex = undefined;
        if ($scope.parameters.daysOldModifier) {
            $scope.trendingEndDate = new Date();
            if ($scope.parameters.daysOldModifier === "LastYear") {
                $scope.trendingStartDate = new Date($scope.trendingEndDate.getFullYear(), $scope.trendingEndDate.getMonth() - 11, 1);
            } else if ($scope.parameters.daysOldModifier === "LastQuarter") {
                $scope.trendingStartDate = new Date($scope.trendingEndDate.getFullYear(), $scope.trendingEndDate.getMonth() - 2, 1);
            };
        } else {
            if ($scope.parameters.endDate) {
                $scope.trendingEndDate = $scope.parameters.endDate;
            }
            if ($scope.parameters.startDate) {
                $scope.trendingStartDate = $scope.parameters.startDate;
            }
        };

//        if (!$scope.trendingStartDate && !$scope.trendingEndDate)
//            return;
        if (!$scope.trendingStartDate) {
            startIndex = 0;
            $scope.trendingStartDate = $scope.filterScans[0].importTime;
        }
        if (!$scope.trendingEndDate ) {
            endIndex = $scope.filterScans.length - 1;
            $scope.trendingEndDate = new Date();
        }

        $scope.filterScans.some(function(scan, index) {
            if (startIndex && endIndex)
                return true;
            if (!startIndex && $scope.trendingStartDate && $scope.trendingStartDate<=scan.importTime)
                startIndex = index;
            if (!endIndex && $scope.trendingEndDate && $scope.trendingEndDate < scan.importTime)
                endIndex = index - 1;
        });

        if (!startIndex && endIndex) startIndex = 0;
        if (startIndex && !endIndex) endIndex = $scope.filterScans.length - 1;

//        if ($scope.trendingStartDate)
//            $scope.trendingStartDate = $scope.trendingStartDate.getTime();
//        if ($scope.trendingEndDate)
//            $scope.trendingEndDate = $scope.trendingEndDate.getTime();
    };

    var endsWith = function(str, suffix) {
        return str.indexOf(suffix, str.length - suffix.length) !== -1;
    };

    var beginsWith = function(str, prefix) {
        return str.indexOf(prefix) == 0;
    };

});
