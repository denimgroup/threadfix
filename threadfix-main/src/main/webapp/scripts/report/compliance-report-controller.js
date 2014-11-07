var module = angular.module('threadfix');

module.controller('ComplianceReportController', function($scope, $rootScope, $window, $http, tfEncoder, reportUtilities, vulnSearchParameterService) {

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

        // Data for trending chart and table
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
        } else {
            refreshScans();
        }

        retrieveVulnList();
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
        var hashBefore, hashAfter;
        reportUtilities.createTeamAppNames($scope);
        $scope.complianceScansData = [];
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
                    $scope.complianceScansData.push(_scan);

            });

            if ($scope.complianceScansData.length===1 && $scope.trendingStartDate == $scope.trendingEndDate) {
                $scope.trendingEndDate = (new Date()).getTime();
                var time = new Date($scope.complianceScansData[0].importTime);
                $scope.trendingStartDate = (new Date(time.getFullYear(), time.getMonth() - 1, 1)).getTime();
            }

            if ($scope.complianceScansData.length > 0) {
                $scope.complianceScansData.unshift(createStartHash(hashBefore));
                $scope.complianceScansData.push(createEndHash(hashAfter));
            }
        };

        renderTable();
    };

    var createStartHash = function(hashBefore) {
        var startHash = {};
        if ($scope.complianceScansData.length===0)
            return startHash;
        var firstHashInList = $scope.complianceScansData[0];

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
    };

    var createEndHash = function(hashAfter) {
        var endHash = {};
        if ($scope.complianceScansData.length===0)
            return endHash;
        var lastHashInList = $scope.complianceScansData[$scope.complianceScansData.length-1];

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
    };

    var renderTable = function() {
        var startingInfo, endingInfo;
            $scope.tableInfo = [];
        if ($scope.complianceScansData.length> 0) {
            startingInfo = $scope.complianceScansData[0];
            endingInfo = $scope.complianceScansData[$scope.complianceScansData.length-1];
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
    };

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
    };

    $scope.$on('allTrendingScans', function(event, trendingScans) {
        $scope.allScans = trendingScans;
        $scope.gotDataFromTrending = true;
        retrieveVulnList();
//        if ($scope.allScans)
//            refreshScans();
    });

    var retrieveVulnList = function(){
        $scope.resetFilters();
        var parameters = updateParameters();
        loadClosedVulns(parameters);
        loadOpenVulns(parameters);

    };

    var updateParameters = function(){
        var parameters = angular.copy($scope.parameters);

        vulnSearchParameterService.updateParameters($scope, parameters);
        if (parameters.daysOldModifier) {
            var endDate = new Date();
            if (parameters.daysOldModifier === "LastYear") {
                parameters.endDate = endDate.getTime();
                parameters.startDate = (new Date(endDate.getFullYear(), endDate.getMonth() - 11, 1)).getTime();
            } else if ($scope.parameters.daysOldModifier === "LastQuarter") {
                parameters.endDate = endDate.getTime();
                parameters.startDate = (new Date(endDate.getFullYear(), endDate.getMonth() - 2, 1)).getTime();
            };
            parameters.daysOldModifier = undefined;
        } ;
        parameters.page = 1;
        parameters.numberVulnerabilities = 50;

        return parameters;
    }

    var loadOpenVulns = function(parameters) {
        $scope.openVulns = {};
        $scope.loadingOpen = true;
        parameters.showOpen = true;
        parameters.showClosed = false;

        $http.post(tfEncoder.encode("/reports/search"), parameters).
            success(function(data) {
                $scope.loadingOpen = false;
                $scope.openVulns = data.object.vulns;
            }).
            error(function() {
                $scope.loadingOpen = false;
            });
    };

    var loadClosedVulns = function(parameters) {
        $scope.closedVulns = {};
        $scope.loadingClosed = true;
        parameters.showOpen = false;
        parameters.showClosed = true;

        $http.post(tfEncoder.encode("/reports/search"), parameters).
            success(function(data) {
                $scope.loadingClosed = false;
                $scope.closedVulns = data.object.vulns;
            }).
            error(function() {
                $scope.loadingClosed = false;
            });
    };

});
