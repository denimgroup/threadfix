var myAppModule = angular.module('threadfix');

myAppModule.controller('LeftReportController', function ($scope, $window, threadfixAPIService, filterService, trendingUtilities, customSeverityService, $log) {

    // Using this controller is easy; just set up a parent controller with empty and reportQuery fields.
    $scope.empty = $scope.$parent.empty;
    $scope.noData = $scope.$parent.empty;
    $scope.leftMargin = [20, 70, 40, 60];

    if (!$scope.empty) {
        $scope.loadingLeft = true;
    }

    $scope.$on('seeMoreExtension', function(event, extension) {
        $scope.seeMoreExtension = extension;
    });

    var loadLeftReport = function() {
        var start = new Date();
        threadfixAPIService.loadReport("/dashboard/leftReport", $scope.reportQuery).
            success(function(data, status, headers, config) {
                $log.info("left request server took " + ((new Date()).getTime() - start.getTime()) + " ms");
                $scope.allScans = data.object.scanList;
                $scope.savedFilters = data.object.savedFilters;
                customSeverityService.setSeverities(data.object.genericSeverities);

                if ($scope.allScans) {
                    $scope.savedDefaultTrendingFilter = filterService.findDefaultFilter($scope);
                    trendingUtilities.resetFilters($scope);

                    $scope.allScans.sort(function (a, b) {
                        return a.importTime - b.importTime;
                    });

                    $scope.filterScans = $scope.allScans;

                    $scope.trendingScansData = trendingUtilities.refreshScans($scope);
                    $log.info("trendingUtilities.refreshScans took " + ((new Date()).getTime() - start.getTime()) + " ms");

                    var hasResultsFilter = function(scan) {
                        totVuln = 0;
                        if (scan[customSeverityService.getCustomSeverity('Critical')])
                            totVuln += scan[customSeverityService.getCustomSeverity('Critical')];
                        if (scan[customSeverityService.getCustomSeverity('High')])
                            totVuln += scan[customSeverityService.getCustomSeverity('High')];
                        if (scan[customSeverityService.getCustomSeverity('Medium')])
                            totVuln += scan[customSeverityService.getCustomSeverity('Medium')];
                        if (scan[customSeverityService.getCustomSeverity('Low')])
                            totVuln += scan[customSeverityService.getCustomSeverity('Low')];
                        if (scan[customSeverityService.getCustomSeverity('Info')])
                            totVuln += scan[customSeverityService.getCustomSeverity('Info')];
                        return totVuln > 0;
                    };

                    if ($scope.trendingScansData &&
                        $scope.trendingScansData.filter(hasResultsFilter).length == 0) {

                        $scope.noData = true;
                        $scope.trendingScansData = undefined;
                    }

                } else {
                    $scope.noData = true;
                }

                $scope.loadingLeft = false;
            }).
            error(function(data, status, headers, config) {

                // TODO improve error handling and pass something back to the users
                $scope.leftReportFailed = true;
                $scope.loadingLeft = false;
            });
    };

    $scope.$on('rootScopeInitialized', function() {
        $scope.reportQuery = $scope.$parent.reportQuery;
        $scope.label = {
            teamId: $scope.$parent.teamId,
            appId: $scope.$parent.appId

        };
        loadLeftReport();
    });

    var reload = function() {
        $scope.loadingLeft = true;
        $scope.leftReport = null;
        $scope.leftReportFailed = false;
        $scope.empty = false;
        loadLeftReport();
    };

    $scope.$on('scanUploaded', reload);
    $scope.$on('severityChanged', reload);
    $scope.$on('scanDeleted', function(event, shouldReload) {
        if (shouldReload) {
            reload();
        } else {
            $scope.leftReport = null;

            $scope.trendingScansData = null;
            $scope.noData = true;
            $scope.allScans = null;

            $scope.empty = true;
        }
    });
});