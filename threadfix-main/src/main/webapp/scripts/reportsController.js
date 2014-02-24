var myAppModule = angular.module('threadfix')

myAppModule.controller('ReportsController', function ($scope, $window, threadfixAPIService) {

    $scope.loadingLeft = true;
    $scope.loadingRight = true;

    $scope.appId  = $window.location.pathname.match(/([0-9]+)$/)[0];
    $scope.teamId = $window.location.pathname.match(/([0-9]+)/)[0];

    var query = $scope.csrfToken + "&appId=" + $scope.appId + "&orgId=" + $scope.teamId;

    $scope.$watch('csrfToken', function() {
        threadfixAPIService.loadReport("/dashboard/leftReport/" + query).
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

        threadfixAPIService.loadReport("/dashboard/rightReport/" + query).
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