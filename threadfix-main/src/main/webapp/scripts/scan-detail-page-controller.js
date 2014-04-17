var myAppModule = angular.module('threadfix')

myAppModule.controller('ScanDetailPageController', function ($scope, $window, $http, $rootScope, tfEncoder) {

    $scope.scanId  = $window.location.pathname.match(/([0-9]+)$/)[0];
    $scope.teamId = $window.location.pathname.match(/([0-9]+)/)[0];
    $scope.appId = $window.location.pathname.match(/([0-9]+)/)[1];
    $scope.currentUrl = "/organizations/" + $scope.teamId + "/applications/" + $scope.appId + "/scans/" + $scope.scanId;


    $scope.$on('rootScopeInitialized', function() {

    });

    $scope.statistic = function() {
        if ($scope.showStatistic) {
            $scope.showStatistic = false;
            $scope.statisticText = 'Show Statistics';
        } else {
            $scope.showStatistic = true;
            $scope.statisticText = 'Hide Statistics';
        }
    };

    $scope.deleteScan = function(scan) {

        if (confirm('Are you sure you want to delete this scan and all of its results? ' +
            'This will also delete any WAF rules and defects associated with orphaned vulnerabilities.')) {
            $http.post(tfEncoder.encode($scope.currentUrl + '/delete')).
                success(function(data, status, headers, config) {

                    if (data.success) {
                        $window.location.href = tfEncoder.encode("/organizations/" + $scope.teamId + "/applications/" + $scope.appId);
                    } else {
                        $scope.errorMessage = "Something went wrong. " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $log.info("HTTP request for form objects failed.");
                    // TODO improve error handling and pass something back to the users
                    $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
                });
        }
    };

});
