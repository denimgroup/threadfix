var myAppModule = angular.module('threadfix')

myAppModule.controller('DashboardController', function ($scope) {

    $scope.empty = false;

    $scope.$watch('csrfToken', function() {
        $scope.reportQuery = $scope.csrfToken;
    });

    $scope.rightReportTitle = "Top 10 Applications";

});