var module = angular.module('threadfix')

module.controller("ErrorLogsController", function($scope, $http, tfEncoder) {

    $scope.numberToShow = 50;

    var bytesToMessage = function(number) {
        var unit = "bytes";
        var lowerNumber = number;

        if (lowerNumber > 1000) {
            lowerNumber = lowerNumber / 1000;
            unit = "kilobytes";
        }

        if (lowerNumber > 1000) {
            lowerNumber = lowerNumber / 1000;
            unit = "megabytes";
        }

        if (lowerNumber > 1000) {
            lowerNumber = lowerNumber / 1000;
            unit = "gigabytes";
        }

        if (lowerNumber > 1000) {
            lowerNumber = lowerNumber / 1000;
            unit = "terabytes";
        }

        return '' + Math.round(lowerNumber) + ' ' + unit;
    };

    $scope.updatePage = function(page) {
        if (page) {

            $http.get(tfEncoder.encode('/configuration/logs/page/' + page + '/' + $scope.numberToShow)).
                success(function(data, status, headers, config) {

                    if (data.success) {

                        $scope.logs = data.object.logs;
                        $scope.totalLogs = data.object.totalLogs;

                        $scope.logs.forEach(function(log) {
                            log.freeMemory = bytesToMessage(log.freeMemory);
                            log.totalMemory = bytesToMessage(log.totalMemoryAvailable);
                            log.freeDiskSpace = bytesToMessage(log.totalSpaceAvailable);

                            if (data.object.logIdToExpand && data.object.logIdToExpand === log.id) {
                                log.expanded = true;
                            }
                        });

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
    };

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