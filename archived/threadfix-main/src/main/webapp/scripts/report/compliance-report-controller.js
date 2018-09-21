var module = angular.module('threadfix');

module.controller('ComplianceReportController', function($scope, $rootScope, $window, $http, tfEncoder, reportUtilities, trendingUtilities, reportConstants, reportExporter) {

    $scope.parameters = {};
    $scope.filterScans = [];
    $scope.noData = false;
    $scope.margin = [70, 70, 100, 70];

    $scope.resetFilters = function() {
        if ($scope.remediationType === 2 && $scope.currentTag) {
            $scope.addNewTag($scope.currentTag);
        } else {
            $scope.parameters = {
                tags: [],
                severities: {
                    critical: true,
                    high: true,
                    medium: true,
                    low: true,
                    info: true
                },
                daysOldModifier: 'Forever',
                endDate: undefined,
                startDate: undefined,
                remediationType: $scope.remediationType
            };
        }
    };

    $scope.$on('loadComplianceReport', function() {
        $scope.noData = false;

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
                        $scope.filterScans = trendingUtilities.filterByTag($scope.allScans, $scope.parameters.tags);
                        $scope.trendingScansData = trendingUtilities.refreshScans($scope);
                    }).
                    error(function() {
                        $scope.loading = false;
                    });
            }
        }
        else {
            $scope.filterScans = trendingUtilities.filterByTag($scope.allScans, $scope.parameters.tags);
            $scope.trendingScansData = trendingUtilities.refreshScans($scope);
        }
        $scope.title.svgId = getReportType().name;
        renderTable();

    });

    $scope.$on('resetParameters', function(event, parameters) {
        refreshData(parameters);
    });

    var refreshData = function(parameters) {
        if (!$scope.$parent.complianceActive
            && !$scope.$parent.remediationActive)
            return;

        if ($scope.remediationType !== parameters.remediationType)
            return;

        $scope.parameters = angular.copy(parameters);

        // Compliance report: query by the selected tag from dropdown
        if ($scope.remediationType == 2) {
            $scope.parameters.tags = [{name: $scope.currentTag}];
        }

        $scope.filterScans = trendingUtilities.filterByTag($scope.allScans, $scope.parameters.tags);
        $scope.trendingScansData = trendingUtilities.refreshScans($scope);
        renderTable();
        $scope.$broadcast("updateTableVulnerabilities");
    };

    $scope.$on('updateDisplayData', function(event, parameters) {
        if (!$scope.$parent.complianceActive
            && !$scope.$parent.remediationActive)
            return;
        if ($scope.remediationType !== parameters.remediationType)
            return;
        $scope.parameters = angular.copy(parameters);
        $scope.trendingScansData = trendingUtilities.refreshScans($scope);
        renderTable();
        $scope.$broadcast("updateTableVulnerabilities");
    });

    var severityOrder = {'Info': 1, 'Low': 2, 'Medium': 3, 'High': 4, 'Critical': 5};

    var renderTable = function() {
        var startingInfo, endingInfo;
        $scope.tableInfo = [];
        if ($scope.trendingScansData && $scope.trendingScansData.length> 0) {
            startingInfo = (trendingUtilities.getFirstHashInList()) ? trendingUtilities.getFirstHashInList() : $scope.trendingScansData[0];
            endingInfo = (trendingUtilities.getLastHashInList()) ? trendingUtilities.getLastHashInList() : $scope.trendingScansData[$scope.trendingScansData.length-1];

            Object.keys(startingInfo).forEach(function(key){
                if (key !== 'importTime' && key !== 'notRealScan') {
                    var map = {};
                    map['Severity'] = key;
                    map['Starting Count'] = startingInfo[key];
                    map['Ending Count'] = endingInfo[key];
                    $scope.tableInfo.push(map);
                }
            });
            $scope.tableInfo.sort(function(a, b){
                return severityOrder[b.Severity] - severityOrder[a.Severity];
            })
        } else {
            $scope.noData = true;
        }
    };

    $scope.$on('allTrendingScans', function(event, trendingScans) {
        $scope.allScans = trendingScans;
        $scope.gotDataFromTrending = true;
        $scope.resetFilters();
    });

    $scope.exportPNG = function(isPDF){
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
        $scope.exportInfo.isPDF = isPDF;
    };

    $scope.exportPDF = function(){

        $scope.exportingPDF = true;

        var reportType = getReportType();
        $scope.numberVulnType = 0;
        $scope.exportInfo = {};
        $scope.exportInfo.svgId = reportType.name;
        $scope.exportInfo.tags = $scope.title.tags;
        $scope.exportInfo.teams = undefined;
        $scope.exportInfo.apps = undefined;
        $scope.exportInfo.title = "Compliance_Report";

        reportExporter.exportPDFTableFromId($scope, $scope.exportInfo, $scope.tableInfo, function() {
            $scope.exportingPDF = false;
        });

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
                $scope.currentTag = name;
                return true;
            }
        });

        $scope.parameters.tags = [];
        $scope.parameters.tags.push({name: name});
        $scope.parameters.remediationType = $scope.remediationType;
    };

});
