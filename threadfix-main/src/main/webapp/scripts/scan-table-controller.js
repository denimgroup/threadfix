var myAppModule = angular.module('threadfix')

myAppModule.controller('ScanTableController', function ($scope, $window, $http, $log, threadfixAPIService) {

    $scope.heading = '0 Scans';
//    $scope.csrfToken = $scope.$parent.$csrfToken;

    $scope.deleteScan = function(scan) {

        $http.post($window.location.pathname + '/scans/' + scan.id + '/delete' + $scope.csrfToken).
            success(function(data, status, headers, config) {

                if (data.success) {
                    var index = $scope.scans.indexOf(scan);

                    if (index > -1) {
                        $scope.wafs.splice(index, 1);
                    }

                } else {
                    $scope.errorMessage = "Something went wrong. " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $log.info("HTTP request for form objects failed.");
                // TODO improve error handling and pass something back to the users
                $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
            });
    };

    $scope.goToScan = function(scan) {
        window.location.href = '/organizations/' + $scope.application.team.id + '/applications/' + $scope.application.team.id  + '/scans/' + scan.id + $scope.csrfToken;

    };

    $scope.$on('applicationInfo', function(event, application) {
        $scope.application = application;
        $scope.scans = application.scans;
        if (!$scope.scans || !$scope.scans.length > 0) {
            $scope.scans = undefined;
        } else {
            $scope.heading = $scope.scans.length + ' Scans';
        }

    });

    $scope.$on('scanUploaded', function() {
        $scope.empty = false;
        refresh();
    });

});