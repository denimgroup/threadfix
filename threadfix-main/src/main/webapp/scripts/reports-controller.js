var myAppModule = angular.module('threadfix')

myAppModule.controller('ReportsController', function ($scope, $window, threadfixAPIService) {

    // Using this controller is easy; just set up a parent controller with empty and reportQuery fields.
    $scope.empty = $scope.$parent.empty;
    $scope.leftMargin = [20, 70, 30, 60];
    $scope.rightMargin = {top: 20, right: 20, bottom: 30, left: 60};

    if (!$scope.empty) {
        $scope.loadingLeft = true;
        $scope.loadingRight = true;
    }

    $scope.$on('seeMoreExtension', function(event, extension) {
        $scope.seeMoreExtension = extension;
    });

    var loadReports = function() {
        threadfixAPIService.loadReport("/dashboard/leftReport", $scope.reportQuery).
            success(function(data, status, headers, config) {

                $scope.trendingData = data.object;

                if (!$scope.trendingData) {
                    $scope.empty = true;
                }

                $scope.loadingLeft = false;
            }).
            error(function(data, status, headers, config) {

                // TODO improve error handling and pass something back to the users
                $scope.leftReportFailed = true;
                $scope.loadingLeft = false;
            });

        threadfixAPIService.loadReport("/dashboard/rightReport", $scope.reportQuery).
            success(function(data, status, headers, config) {

                $scope.topAppsData = data.object;

                if (!$scope.topAppsData) {
                    $scope.empty = true;
                }

                $scope.loadingRight = false;

            }).
            error(function(data, status, headers, config) {

                // TODO improve error handling and pass something back to the users
                $scope.rightReportFailed = true;
                $scope.loadingRight = false;
            });
    };

    $scope.$on('rootScopeInitialized', function() {
        $scope.reportQuery = $scope.$parent.reportQuery;
        $scope.label = {
            teamId: $scope.$parent.teamId,
            appId: $scope.$parent.appId

        };
        $scope.rightReportTitle = $scope.$parent.rightReportTitle;
        if (!$scope.empty) {
            loadReports();
        }
    });

    var reload = function() {
        $scope.loadingLeft = true;
        $scope.leftReport = null;
        $scope.loadingRight = true;
        $scope.rightReport = null;
        $scope.rightReportFailed = false;
        $scope.leftReportFailed = false;
        $scope.empty = false;
        loadReports();
    };

    $scope.$on('scanUploaded', reload);
    $scope.$on('scanDeleted', function(event, shouldReload) {
        if (shouldReload) {
            reload();
        } else {
            $scope.leftReport = null;
            $scope.rightReport = null;
            $scope.empty = true;
        }
    });

});