var myAppModule = angular.module('threadfix')

myAppModule.controller('FindingDetailPageController', function ($scope, $window, $http, $rootScope, tfEncoder, $modal, $log, vulnSearchParameterService) {

    $scope.scanId  = $window.location.pathname.match(/scans\/([0-9]+)/)[1];
    $scope.teamId = $window.location.pathname.match(/organizations\/([0-9]+)/)[1];
    $scope.appId = $window.location.pathname.match(/applications\/([0-9]+)/)[1];
    $scope.findingId = $window.location.pathname.match(/findings\/([0-9]+)/)[1];
    $scope.currentUrl = "/organizations/" + $scope.teamId + "/applications/" + $scope.appId + "/scans/" + $scope.scanId + "/findings/" + $scope.findingId;

    $scope.badgeClassMap = {
        5:"badge-critical",
        4:"badge-high",
        3:"badge-medium",
        2:"badge-low",
        1:"badge-info"
    };

    $scope.$on('rootScopeInitialized', function() {
        $scope.refresh();
    });

    var getAppUrl = function(vulnerability) {
        return tfEncoder.encode("/organizations/" + vulnerability.team.id + "/applications/" + vulnerability.app.id);
    };

    var getTeamUrl = function(vulnerability) {
        return tfEncoder.encode("/organizations/" + vulnerability.team.id);
    };

    var getVulnUrl = function(vulnerability) {
        return tfEncoder.encode("/organizations/" + vulnerability.team.id + "/applications/" + vulnerability.app.id + "/vulnerabilities/" + vulnerability.id);
    }

    $scope.refresh = function() {
        $http.get(tfEncoder.encode($scope.currentUrl + '/table')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.sharedVulns = data.object.sharedVulns;

                    $scope.sharedVulns.forEach(function(vuln){
                        vuln.appUrl = getAppUrl(vuln);
                        vuln.teamUrl = getTeamUrl(vuln);
                        vuln.vulnUrl = getVulnUrl(vuln);
                    });

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    };

});
