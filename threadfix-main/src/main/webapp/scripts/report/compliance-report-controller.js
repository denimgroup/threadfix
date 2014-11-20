var module = angular.module('threadfix');

module.controller('ComplianceReportController', function($scope, $rootScope, $window, $http, tfEncoder, reportUtilities, trendingUtilities, reportConstants) {

    $scope.parameters = {};
    $scope.filterScans = [];
    $scope.noData = false;
    $scope.margin = [70, 70, 100, 70];

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
            startDate: undefined,
            remediationType: $scope.remediationType
        };
    };

    $scope.$on('loadComplianceReport', function() {
        $scope.noData = false;
        $scope.savedFilters = $scope.$parent.savedFilters.filter(function(filter){
            var parameters = JSON.parse(filter.json);
            return (parameters.filterType && parameters.filterType.isComplianceFilter);
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

                        if (!$scope.allScans) {
                            $scope.allScans = [];
                        }
                        $scope.allScans.sort(function (a, b) {
                            return a.importTime - b.importTime;
                        });
                        trendingUtilities.filterByTag($scope);
                        trendingUtilities.refreshScans($scope);
                    }).
                    error(function() {
                        $scope.loading = false;
                    });
            }
        }
        else {
            trendingUtilities.filterByTag($scope);
            trendingUtilities.refreshScans($scope);
        }
        $scope.title.svgId = getReportType().name;
        renderTable();

    });

    $scope.$on('resetParameters', function(event, parameters) {
        refreshData(parameters);
    });

    var refreshData = function(parameters) {
        if (!$scope.$parent.complianceActive
            && !$scope.$parent.remediationEnterpriseActive)
            return;

        if ($scope.remediationType !== parameters.remediationType)
            return;

        $scope.parameters = angular.copy(parameters);
        trendingUtilities.filterByTag($scope);
        trendingUtilities.refreshScans($scope);
        renderTable();
        $scope.$broadcast("updateTableVulnerabilities");
    };


    $scope.$on('updateDisplayData', function(event, parameters) {
        if (!$scope.$parent.complianceActive
            && !$scope.$parent.remediationEnterpriseActive)
            return;
        if ($scope.remediationType !== parameters.remediationType)
            return;
        $scope.parameters = angular.copy(parameters);
        trendingUtilities.updateDisplayData($scope);
        renderTable();
        $scope.$broadcast("updateTableVulnerabilities");
    });

    var renderTable = function() {
        var startingInfo, endingInfo;
            $scope.tableInfo = [];
        if ($scope.trendingScansData.length> 0) {
            startingInfo = (trendingUtilities.getFirstHashInList()) ? trendingUtilities.getFirstHashInList() : $scope.trendingScansData[0];
            endingInfo = (trendingUtilities.getLastHashInList()) ? trendingUtilities.getLastHashInList() : $scope.trendingScansData[$scope.trendingScansData.length-1];
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

    $scope.$on('allTrendingScans', function(event, trendingScans) {
        $scope.allScans = trendingScans;
        $scope.gotDataFromTrending = true;
        $scope.resetFilters();
    });

    $scope.exportPNG = function(){
        var reportType = getReportType();
        if (!$scope.exportInfo) {
            $scope.exportInfo = {
                id: reportType.id
            }
        } else {
            if ($scope.exportInfo.id  === reportType.id)
                $scope.exportInfo.id  = "" +  reportType.id;
            else
                $scope.exportInfo.id  = reportType.id;
        }
        $scope.exportInfo.svgId = reportType.name;
        $scope.exportInfo.tags = $scope.title.tags;
        $scope.exportInfo.teams = undefined;
        $scope.exportInfo.apps = undefined;
    };

    var getReportType = function() {
        if ($scope.$parent.complianceActive)
            return reportConstants.reportTypes.compliance;
        else
            return reportConstants.reportTypes.complianceEnterprise;
    };

    $scope.addNewTag = function(name) {

        if ($scope.remediationType !== 2)
            return;
        getDefaultTagFilter(name);
        refreshData($scope.parameters);
        $scope.$broadcast("updateBackParameters", $scope.parameters);

    };

    var getDefaultTagFilter = function(name) {
        $scope.enterpriseTags = $scope.$parent.enterpriseTags;
        $scope.enterpriseTags.some(function(tag) {
            if (tag.name === name) {
                $scope.parameters =  JSON.parse(tag.defaultJsonFilter);
                return true;
            }
        });

        $scope.parameters.tags = [];
        $scope.parameters.tags.push({name: name});
        $scope.parameters.remediationType = $scope.remediationType;
    }


});
