var module = angular.module('threadfix');

module.controller('TrendingReportController', function($scope, $rootScope, $window, $http, tfEncoder, reportUtilities, filterService, trendingUtilities, reportConstants) {

    $scope.parameters = {};
    $scope.filterScans = [];
    $scope.noData = false;
    $scope.margin = [60, 70, 100, 60];
    $scope.savedDefaultTrendingFilter = undefined;
    $scope.title = {
        svgId: reportConstants.reportTypes.trending.name
    };

    $scope.resetFilters = function() {
        trendingUtilities.resetFilters($scope);
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

                    if (!$scope.allScans) {
                        $scope.allScans = [];
                    }
                    $scope.allScans.sort(function (a, b) {
                        return a.importTime - b.importTime;
                    });
                    trendingUtilities.filterByTeamAndApp($scope);
                    trendingUtilities.refreshScans($scope);

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
        trendingUtilities.filterByTeamAndApp($scope);
        trendingUtilities.refreshScans($scope);
    });

    $scope.$on('updateDisplayData', function(event, parameters) {
        if (!$scope.$parent.trendingActive)
            return;
        $scope.parameters = angular.copy(parameters);
        trendingUtilities.updateDisplayData($scope);
    });

    $scope.exportPNG = function(){
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
    };

});
