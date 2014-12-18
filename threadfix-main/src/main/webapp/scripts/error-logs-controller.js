var module = angular.module('threadfix')

module.controller("ErrorLogsController", function($scope, $http, tfEncoder) {

    $scope.numberToShow = 50;

    $scope.updatePage = function(page) {
        if (page) {

            $http.get(tfEncoder.encode('/configuration/logs/page/' + page + '/' + $scope.numberToShow)).
                success(function(data, status, headers, config) {

                    if (data.success) {

                        $scope.logs = data.object.logs;
                        $scope.totalLogs = data.object.totalLogs;

                    } else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }

                    $scope.initialized = true;
                }).
                error(function(data, status, headers, config) {
                    $scope.initialized = true;
                    $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
                });
        }
    }

    $scope.$watch('page', function() {
        if ($scope.initialized) {
            $scope.updatePage($scope.page);
        }
    });


    $scope.$on('rootScopeInitialized', function() {
        $scope.page = 1;
        $scope.updatePage(1);
    });




});