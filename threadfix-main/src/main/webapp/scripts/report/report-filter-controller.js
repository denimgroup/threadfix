var module = angular.module('threadfix');

module.controller('ReportFilterController', function($scope, $rootScope, $window, $http, tfEncoder) {

    $scope.parameters = {};
    $scope.filterScans = [];
    $scope.noData = false;

    $scope.resetFilters = function() {
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
            daysOld: 'LastYear',
            endDate: undefined,
            startDate: undefined
        };
    };

    $scope.toggleAllFilters = function() {
        if ($scope.showTeamAndApplicationControls
            || $scope.showDetailsControls
            || $scope.showDateControls
            || $scope.showDateRange) {
            $scope.showTeamAndApplicationControls = false;
            $scope.showDetailsControls = false;
            $scope.showDateControls = false;
            $scope.showDateRange = false;
        } else {
            $scope.showTeamAndApplicationControls = true;
            $scope.showDetailsControls = true;
            $scope.showDateControls = true;
            $scope.showDateRange = true;
        }
    };

    $scope.maxDate = new Date();

    $scope.openEndDate = function($event) {
        resetAging();
        $event.preventDefault();
        $event.stopPropagation();

        $scope.endDateOpened = true;
    };

    $scope.openStartDate = function($event) {
        resetAging();
        $event.preventDefault();
        $event.stopPropagation();

        $scope.startDateOpened = true;
    };

    var resetAging = function() {
        $scope.parameters.daysOld = undefined;
    };

    $scope.$on('loadTrendingReport', function() {

        $scope.noData = false;

        if (!$scope.allScans) {
            $scope.loading = true;
            $http.post(tfEncoder.encode("/reports/trendingScans"), $scope.getReportParameters()).
                success(function(data, status, headers, config) {

                    $scope.reportHTML = undefined;
                    $scope.loading = false;

                    $scope.trendingScansData = data.object.trendingScans;
                    $scope.resetFilters();
                    $scope.allScans = data.object.scanList;

                    if ($scope.allScans) {
                        $scope.allScans.sort(function (a, b) {
                            return a.importTime - b.importTime;
                        });
                        $scope.refreshScans();

                    } else {
                        $scope.noData = true;
                    };

                }).
                error(function(data, status, headers, config) {

                    $scope.loading = false;
                });
        } else {

        }
    });

    $scope.refreshScans = function(){
        $scope.loading = true;
        filterByTeamAndApp();
        filterByTime();
        if ($scope.filterScans.length === 0) {
            $scope.noData = true;
        } else {
            $scope.noData = false;
        }
        $scope.refresh();
        $scope.loading = false;
    };

    var updateDisplayData = function(){
        var teams;
        var apps;
        if ($scope.parameters.teams.length === 0 && $scope.parameters.applications.length === 0) {
            teams = "All";
            apps = "All";
        }
        else {
            if ($scope.parameters.teams.length > 0) {
                teams = $scope.parameters.teams[0].name;
            }
            var i;
            for (i=1; i<$scope.parameters.teams.length; i++) {
                teams += ", " + $scope.parameters.teams[i].name;
            }

            if ($scope.parameters.applications.length > 0) {
                apps = $scope.parameters.applications[0].name;
            }
            for (i=1; i<$scope.parameters.applications.length; i++) {
                apps += ", " + $scope.parameters.applications[i].name;
            }
        }

        $scope.title = {
            teams: teams,
            apps: apps

        };
        $scope.trendingScansData = [];
        $scope.totalVulnsByChannelMap = {};
        $scope.infoVulnsByChannelMap = {};
        $scope.lowVulnsByChannelMap = {};
        $scope.mediumVulnsByChannelMap = {};
        $scope.highVulnsByChannelMap = {};
        $scope.criticalVulnsByChannelMap = {};
        $scope.filterScans.forEach(function(scan){
            $scope.trendingScansData.push(filterDisplayData(scan));
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
        var startDate;
        var endDate;
        if ($scope.parameters.daysOld) {
            endDate = new Date();
            if ($scope.parameters.daysOld === "LastYear") {
                startDate = new Date(endDate.getFullYear(), endDate.getMonth() - 11, 1);
            } else if ($scope.parameters.daysOld === "LastQuarter") {
                startDate = new Date(endDate.getFullYear(), endDate.getMonth() - 2, 1);
            } else if ($scope.parameters.daysOld === "Forever") {

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
        $scope.filterScans = $scope.filterScans.filter(function(scan){
            return (!startDate || (startDate && startDate.getTime() <= scan.importTime)) &&
                (!endDate || (endDate && endDate.getTime() >= scan.importTime));
        });

    };

    $scope.refresh = function() {
        updateDisplayData();
    };


    $scope.addNew = function(collection, name) {
        var found = false;

        collection.forEach(function(item) {
            if (item && item.name === name) {
                found = true;
            }
        });

        if (!found) {
            collection.push({name: name});
            $scope.refreshScans();
        }
    };

    $scope.remove = function(collection, index) {
        collection.splice(index, 1);
        $scope.refreshScans();
    };

    $scope.setDaysOld = function(days) {
        resetDateRange();
        if ($scope.parameters.daysOld === days) {
            $scope.parameters.daysOld = undefined;
        } else {
            $scope.parameters.daysOld = days;

        }
        $scope.refreshScans();
    };

    var resetDateRange = function(){
        // Reset Date Range
        $scope.parameters.startDate = null;
        $scope.startDateOpened = false;
        $scope.parameters.endDate = null;
        $scope.endDateOpened = false;
    };

    var endsWith = function(str, suffix) {
        return str.indexOf(suffix, str.length - suffix.length) !== -1;
    };

    var beginsWith = function(str, prefix) {
        return str.indexOf(prefix) == 0;
    };

});
