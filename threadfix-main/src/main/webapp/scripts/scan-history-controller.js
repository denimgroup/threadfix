var myAppModule = angular.module('threadfix');

myAppModule.controller('ScanHistoryController', function($scope, $log, $http, $window, tfEncoder) {

    $scope.initialized = false;

    $scope.page = 1;
    $scope.numScans = 0;

    // since we need the csrfToken to make the request, we need to wait until it's initialized
    $scope.$on('rootScopeInitialized', function() {
        $scope.refresh(true, false);
    });

    $scope.refresh = function(newValue, oldValue) {
        if (newValue !== oldValue) {
            $scope.loading = true;
            $http.post(tfEncoder.encode("/scans/table/" + $scope.page)).
                success(function(data, status, headers, config) {
                    $scope.initialized = true;

                    if (data.success) {
                        $scope.scans = data.object.scanList;
                        $scope.numScans = data.object.numScans;
                        $scope.numberOfPages = Math.ceil(data.object.numScans/100);

                    } else {
                        $scope.output = "Failure. Message was : " + data.message;
                    }
                    $scope.loading = false;
                }).
                error(function(data, status, headers, config) {
                    $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                    $scope.loading = false;
                });
        }
    };

    $scope.$watch('page', $scope.refresh);

    $scope.goToPage = function(valid) {
        if (valid) {
            $scope.page = $scope.pageInput;
        }
    };

    $scope.goTo = function(scan) {
        $window.location.href = tfEncoder.encode("/organizations/" + scan.team.id + "/applications/" + scan.app.id + "/scans/" + scan.id);
    };

});
