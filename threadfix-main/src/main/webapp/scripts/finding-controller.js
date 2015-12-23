var myAppModule = angular.module('threadfix');

myAppModule.controller('FindingController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder) {

    $scope.appId  = $window.location.pathname.match(/applications\/([0-9]+)/)[1];
    $scope.teamId = $window.location.pathname.match(/organizations\/([0-9]+)/)[1];
    $scope.scanId = $window.location.pathname.match(/scans\/([0-9]+)/)[1];
    $scope.findingId = $window.location.pathname.match(/findings\/([0-9]+)$/)[1];
    $scope.currentUrl = "/organizations/" + $scope.teamId + "/applications/" + $scope.appId + "/scans/"
        + $scope.scanId + "/findings/" + $scope.findingId;

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode($scope.currentUrl + "/objects")).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.finding = data.object.finding;

                    if (data.object.isEnterprise) {
                        $rootScope.$broadcast('sourceCodeData', data.object.sourceCodeData);
                    }

                } else {
                    $log.info("HTTP request for form objects failed. Error was " + data.message);
                }
            }).
            error(function(data, status, headers, config) {
                $log.info("HTTP request for form objects failed.");
                // TODO improve error handling and pass something back to the users
                $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
            });
    });

    $scope.goToTeam = function() {
        window.location.href = tfEncoder.encode("/organizations/" + $scope.teamId);
    };

    $scope.goToApplication = function() {
        window.location.href = tfEncoder.encode("/organizations/" + $scope.teamId + "/applications/" + $scope.appId);
    };

    $scope.goToScan = function() {
        window.location.href = tfEncoder.encode("/organizations/" + $scope.teamId + "/applications/" + $scope.appId +
            "/scans/" + $scope.scanId);
    };

    $scope.goToVulnerability = function() {
        window.location.href = tfEncoder.encode("/organizations/" + $scope.teamId + "/applications/" + $scope.appId +
            "/vulnerabilities/" + $scope.finding.vulnerability.id);
    };

    $scope.goToFindingMerge = function() {
        window.location.href = tfEncoder.encode($scope.currentUrl + "/merge");
    };

});