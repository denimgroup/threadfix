var myAppModule = angular.module('threadfix')

myAppModule.controller('ApplicationDetailPageController', function ($scope, $window, threadfixAPIService) {

    $scope.onFileSelect = function($files) {
        $scope.$broadcast('fileDragged', $files);
    };

    $scope.appId  = $window.location.pathname.match(/([0-9]+)$/)[0];
    $scope.teamId = $window.location.pathname.match(/([0-9]+)/)[0];

    $scope.$watch('csrfToken', function() {
        $scope.reportQuery = $scope.csrfToken + "&appId=" + $scope.appId + "&orgId=" + $scope.teamId;
    });

    $scope.rightReportTitle = "Top 10 Vulnerabilities";

});