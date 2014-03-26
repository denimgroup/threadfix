var myAppModule = angular.module('threadfix')

myAppModule.controller('ScanHistoryController', function($scope, $log, $http, $window) {

    $scope.initialized = false;

    $scope.pageNumber = 1;
    $scope.numScans = 0;

    // since we need the csrfToken to make the request, we need to wait until it's initialized
    $scope.$watch('csrfToken', function() {
        $http.post("/scans/table/" + $scope.pageNumber + $scope.csrfToken).
            success(function(data, status, headers, config) {
                $scope.initialized = true;

                if (data.success) {
                    $scope.scans = data.object.scanList;
                    $scope.numScans = data.object.numScans;

                } else {
                    $scope.output = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.goTo = function(scan) {
        $window.location.href = "/organizations/" + scan.team.id + "/applications/" + scan.app.id + "/scans/" + scan.id + $scope.csrfToken;
    };

});
