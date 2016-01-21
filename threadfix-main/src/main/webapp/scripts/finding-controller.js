var myAppModule = angular.module('threadfix');

myAppModule.controller('FindingController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder, syntaxHighlighterService) {

    $scope.initialized = false;

    var appId = $window.location.pathname.match(/applications\/([0-9]+)/)[1];
    var teamId = $window.location.pathname.match(/organizations\/([0-9]+)/)[1];
    var scanId = $window.location.pathname.match(/scans\/([0-9]+)/)[1];
    var findingId = $window.location.pathname.match(/findings\/([0-9]+)$/)[1];
    var currentUrl = "/organizations/" + teamId + "/applications/" + appId + "/scans/" + scanId +
        "/findings/" + findingId;


    $scope.$on('rootScopeInitialized', function() {

        $scope.teamUrl = tfEncoder.encode("/organizations/" + teamId);
        $scope.appUrl = tfEncoder.encode("/organizations/" + teamId + "/applications/" + appId);
        $scope.scanUrl = tfEncoder.encode("/organizations/" + teamId + "/applications/" + appId + "/scans/" + scanId);

        $http.get(tfEncoder.encode(currentUrl + "/objects")).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.initialized = true;
                    $scope.finding = data.object.finding;
                    $scope.showDataFlowElements = $scope.finding.dataFlowElements && $scope.finding.dataFlowElements.length > 0;
                    $scope.isEnterprise = data.object.isEnterprise;

                    $scope.vulnUrl = tfEncoder.encode("/organizations/" + teamId + "/applications/" + appId +
                        "/vulnerabilities/" + $scope.finding.vulnerability.id);
                    $scope.mergeUrl = tfEncoder.encode(currentUrl + "/merge");

                    if ($scope.showDataFlowElements) {
                        $scope.finding.dataFlowElements.forEach(function (dataFlowElement) {
                            dataFlowElement.highlightedContent = dataFlowElement.lineText;
                            dataFlowElement.classes = syntaxHighlighterService.getSyntaxHighlightClasses(dataFlowElement.sourceFileName);
                        });
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
});