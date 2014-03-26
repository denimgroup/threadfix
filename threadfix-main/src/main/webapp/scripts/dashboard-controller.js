var myAppModule = angular.module('threadfix')

myAppModule.controller('DashboardController', function ($scope, $rootScope) {

    $scope.empty = false;

    $scope.$on('rootScopeInitialized', function() {
        $scope.reportQuery = $rootScope.csrfToken;
    });

    $scope.rightReportTitle = "Top 10 Applications";

});