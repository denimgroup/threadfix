var myAppModule = angular.module('threadfix')

myAppModule.controller('DashboardController', function ($scope, threadfixAPIService) {

    $scope.loadingLeft = true;
    $scope.loadingRight = true;

    $scope.$watch('csrfToken', function() {
        threadfixAPIService.loadReport("/dashboard/leftReport/" + $scope.csrfToken).
            success(function(data, status, headers, config) {
                // TODO figure out Jasper better, it's a terrible way to access the report images.
                var matches = data.match(/(<img src="\/jasperimage\/.*\/img_0_0_0" style="height: 250px" alt=""\/>)/);
                if (matches !== null && matches[1] !== null) {
                    $scope.leftReport = matches[1];
                } else {
                    $scope.leftReportFailed = true;
                }
            }).
            error(function(data, status, headers, config) {

                // TODO improve error handling and pass something back to the users
                $scope.leftReportFailed = true;
            });

        threadfixAPIService.loadReport("/dashboard/rightReport/" + $scope.csrfToken).
            success(function(data, status, headers, config) {
                // TODO figure out Jasper better, it's a terrible way to access the report images.
                var matches = data.match(/(<img src="\/jasperimage\/.*\/img_0_0_0" style="height: 250px" alt=""\/>)/);
                if (matches !== null && matches[1] !== null) {
                    $scope.rightReport = matches[1];
                } else {
                    $scope.rightReportFailed = true;
                }
            }).
            error(function(data, status, headers, config) {

                // TODO improve error handling and pass something back to the users
                $scope.rightReportFailed = true;
            });
    });


});