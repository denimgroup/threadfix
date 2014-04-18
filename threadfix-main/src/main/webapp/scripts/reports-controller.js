var myAppModule = angular.module('threadfix')

myAppModule.controller('ReportsController', function ($scope, $window, threadfixAPIService) {

    // Using this controller is easy; just set up a parent controller with empty and reportQuery fields.
    $scope.empty = $scope.$parent.empty;

    if (!$scope.empty) {
        $scope.loadingLeft = true;
        $scope.loadingRight = true;
    }

    var loadReports = function() {
        threadfixAPIService.loadReport("/dashboard/leftReport", $scope.reportQuery).
            success(function(data, status, headers, config) {
                // TODO figure out Jasper better, it's a terrible way to access the report images.
                var matches = data.match(/(<img src=".*\/jasperimage\/.*\/img_0_0_0" style="height: 250px" alt=""\/>)/);
                if (matches !== null && matches[1] !== null) {
                    $scope.leftReport = matches[1];
                } else if (data.indexOf("No data found") !== -1) {
                    $scope.empty = true;
                } else {
                    $scope.leftReportFailed = true;
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
                // TODO figure out Jasper better, it's a terrible way to access the report images.
                var matches = data.match(/(<img src=".*\/jasperimage\/.*\/img_0_0_0" style="height: 250px" alt=""\/>)/);
                if (matches !== null && matches[1] !== null) {
                    $scope.rightReport = matches[1];
                } else if (data.indexOf("No data found") !== -1) {
                    $scope.empty = true;
                } else {
                    $scope.rightReportFailed = true;
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
    }

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