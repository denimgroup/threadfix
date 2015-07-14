var myAppModule = angular.module('threadfix');

myAppModule.controller('RightReportController', function ($scope, $window, threadfixAPIService, $log) {

    // Using this controller is easy; just set up a parent controller with empty and reportQuery fields.
    $scope.empty = $scope.$parent.empty;
    $scope.noData = $scope.$parent.empty;
    $scope.rightMargin = {top: 20, right: 20, bottom: 30, left: 60};

    if (!$scope.empty) {
        $scope.loadingRight = true;
    }

    $scope.$on('seeMoreExtension', function(event, extension) {
        $scope.seeMoreExtension = extension;
    });

    var loadRightReport = function() {
        var start = new Date();
        threadfixAPIService.loadReport("/dashboard/rightReport", $scope.reportQuery).
            success(function(data, status, headers, config) {
                $log.info("right request server took " + ((new Date()).getTime() - start.getTime()) + " ms");
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
            loadRightReport();
        }
    });

    var reload = function() {
        $scope.loadingRight = true;
        $scope.rightReport = null;
        $scope.rightReportFailed = false;
        $scope.empty = false;
        loadRightReport();
    };

    $scope.$on('scanUploaded', reload);

    $scope.$on('scanDeleted', function(event, shouldReload) {
        if (shouldReload) {
            reload();
        } else {
            $scope.rightReport = null;

            $scope.topAppsData = null;
            $scope.noData = true;
            $scope.allScans = null;

            $scope.empty = true;
        }
    });
});