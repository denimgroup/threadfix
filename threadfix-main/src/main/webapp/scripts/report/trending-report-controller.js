var module = angular.module('threadfix');

module.controller('TrendingReportController', function($scope, $rootScope, $window, $http, tfEncoder, reportUtilities, filterService, trendingUtilities, reportConstants, reportExporter) {

    $scope.parameters = {};
    $scope.filterScans = [];
    $scope.noData = false;
    $scope.margin = [100, 70, 100, 60];
    $scope.savedDefaultTrendingFilter = undefined;
    $scope.title = {
        svgId: reportConstants.reportTypes.trending.name
    };

    $scope.resetFilters = function() {
        trendingUtilities.resetFilters($scope);
    };

    $scope.$on('loadTrendingReport', function() {
        $scope.noData = false;
        $scope.savedDefaultTrendingFilter = filterService.findDefaultFilter($scope);

        if (!$scope.allScans) {
            $scope.loading = true;
            $http.post(tfEncoder.encode("/reports/trendingScans"), $scope.getReportParameters()).
                success(function(data) {
                    $scope.loading = false;
                    $scope.resetFilters();
                    $scope.allScans = data.object.scanList;
                    $scope.versionsMap = data.object.versionsMap;
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

                    if (!$scope.allScans) {
                        $scope.allScans = [];
                    }
                    $scope.allScans.sort(function (a, b) {
                        return a.importTime - b.importTime;
                    });
                    $scope.filterScans = trendingUtilities.filterByTeamAndApp($scope.allScans, $scope.parameters.teams, $scope.parameters.applications);
                    $scope.trendingScansData = trendingUtilities.refreshScans($scope);
                    $scope.versionsDisplayData = trendingUtilities.filterVersions($scope.parameters, $scope.versionsMap);

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
        $scope.filterScans = trendingUtilities.filterByTeamAndApp($scope.allScans, $scope.parameters.teams, $scope.parameters.applications);
        $scope.filterScans = trendingUtilities.filterByUniqueId($scope.filterScans, $scope.parameters.uniqueIds);
        $scope.filterScans = trendingUtilities.filterByTag($scope.filterScans, $scope.parameters.tags);
        $scope.trendingScansData = trendingUtilities.refreshScans($scope);
        $scope.versionsDisplayData = trendingUtilities.filterVersions($scope.parameters, $scope.versionsMap);
    });

    $scope.$on('updateDisplayData', function(event, parameters) {
        if (!$scope.$parent.trendingActive)
            return;
        $scope.parameters = angular.copy(parameters);
        $scope.trendingScansData = trendingUtilities.refreshScans($scope);
        $scope.versionsDisplayData = trendingUtilities.filterVersions($scope.parameters, $scope.versionsMap);
    });

    $scope.exportPNG = function(isPDF){
        if (!$scope.exportInfo) {
            $scope.exportInfo = {
                id: reportConstants.reportTypes.trending.id
            }
        } else {
            if ($scope.exportInfo.id  === reportConstants.reportTypes.trending.id)
                $scope.exportInfo.id  = "" +  reportConstants.reportTypes.trending.id;
            else
                $scope.exportInfo.id  = reportConstants.reportTypes.trending.id;
        }
        $scope.exportInfo.svgId = reportConstants.reportTypes.trending.name;
        $scope.exportInfo.teams = $scope.title.teams;
        $scope.exportInfo.apps = $scope.title.apps;
        $scope.exportInfo.tags = undefined;
        $scope.exportInfo.isPDF = isPDF;
    };

    $scope.exportPDF = function(){
        $scope.exportInfo = {};
        $scope.exportInfo.svgId = reportConstants.reportTypes.trending.name;
        $scope.exportInfo.teams = $scope.title.teams;
        $scope.exportInfo.apps = $scope.title.apps;
        $scope.exportInfo.tags = $scope.title.tags;
        $scope.exportInfo.title = "Trending_Scans";
        reportExporter.exportPDFTableFromId($scope, $scope.exportInfo)
    };

});
