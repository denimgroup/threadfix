var module = angular.module('threadfix');

module.controller('ComplianceReportController', function($scope, $rootScope, $window, $http, tfEncoder, reportUtilities, filterService) {

    $scope.parameters = {};
    $scope.filterScans = [];
    $scope.noData = false;
    $scope.margin = [70, 70, 100, 70];

    var startIndex, endIndex;

    $scope.resetFilters = function() {
        $scope.parameters = {
            tags: [],
            severities: {
                critical: true,
                high: true,
                medium: true,
                low: true,
                info: true
            },
            daysOldModifier: 'LastYear',
            endDate: undefined,
            startDate: undefined
        };
    };

    $scope.$on('loadComplianceReport', function() {
        $scope.noData = false;
        $scope.savedFilters = $scope.$parent.savedFilters.filter(function(filter){
            var parameters = JSON.parse(filter.json);
            return (parameters.filterType && parameters.filterType.isTrendingFilter);
        });

        if (!$scope.allScans) {
            if ($scope.gotDataFromTrending) {
                $scope.noData = true;
            } else {
                $scope.loading = true;
                $http.post(tfEncoder.encode("/reports/trendingScans"), $scope.getReportParameters()).
                    success(function(data) {
                        $scope.loading = false;
                        $scope.resetFilters();
                        $scope.allScans = data.object.scanList;

                        if ($scope.allScans) {
                            $scope.allScans.sort(function (a, b) {
                                return a.importTime - b.importTime;
                            });
                            refreshScans();
                        } else {
                            $scope.noData = true;
                        };
                    }).
                    error(function() {
                        $scope.loading = false;
                    });
            }
        }
    });

    $scope.$on('resetParameters', function(event, parameters) {
        if (!$scope.$parent.complianceActive)
            return;
        $scope.parameters = angular.copy(parameters);
        refreshScans();
    });

    $scope.$on('updateDisplayData', function(event, parameters) {
        if (!$scope.$parent.complianceActive)
            return;
        $scope.parameters = angular.copy(parameters);
        updateDisplayData();
    });

     var refreshScans = function(){
        $scope.loading = true;
        filterByTag();
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
        renderTable();
    };

    var renderTable = function() {

        var startingInfo, endingInfo;
            $scope.tableInfo = [];
        if ($scope.trendingScansData.length> 0) {
            startingInfo = $scope.trendingScansData[0];
            endingInfo = $scope.trendingScansData[$scope.trendingScansData.length-1];
            var keys = Object.keys(startingInfo);

            keys.forEach(function(key){
                if (key !== 'importTime') {
                    var map = {};
                    map['Severity'] = key;
                    map['Starting Count'] = startingInfo[key];
                    map['Ending Count'] = endingInfo[key];
                    $scope.tableInfo.push(map);
                }
            })



        }
    }

    var filterDisplayData = function(scan) {
        var data = {};
        data.importTime = scan.importTime;

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

    var filterByTag = function() {

        $scope.filterScans = $scope.allScans.filter(function(scan){
            if ($scope.parameters.tags.length === 0 )
                return true;
            var i, j;
            for (i=0; i<$scope.parameters.tags.length; i++) {
                for (j=0; j<scan.applicationTags.length; j++) {
                    if (scan.applicationTags[j].name === $scope.parameters.tags[i].name) {
                        return true;
                    }
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

    $scope.$on('allTrendingScans', function(event, trendingScans) {
        $scope.allScans = trendingScans;
        $scope.gotDataFromTrending = true;
        if ($scope.allScans)
            refreshScans();
    });

});
