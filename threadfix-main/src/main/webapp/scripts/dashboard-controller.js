var myAppModule = angular.module('threadfix');

myAppModule.controller('DashboardController', function ($scope, $rootScope, $http, tfEncoder) {

    $scope.empty = false;

    $scope.$on('rootScopeInitialized', function() {
        $scope.reportQuery = '';

        $http.get(tfEncoder.encode('/feeds/dashboard'))
            .success(function(data, status, headers, config) {

                $rootScope.$broadcast('activityFeed', data.object);

            }).
            error(function(data, status, headers, config) {

                console.log("unable to load activity feed.")
            });

    });

    $scope.rightReportTitle = "Most Vulnerable Applications";

});