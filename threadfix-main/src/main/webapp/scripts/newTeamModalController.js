var myAppModule = angular.module('threadfix')

myAppModule.controller('NewTeamModalController', function ($scope, $modalInstance, threadFixModalService, focus, csrfToken) {

    focus("open");

    $scope.team = {};

    $scope.loading = false;

    $scope.ok = function (valid) {

        if (valid) {
            $scope.loading = true;

            var url = "/organizations/modalAdd" + csrfToken;

            threadFixModalService.post(url, $scope.team).
                success(function(data, status, headers, config) {
                    $scope.loading = false;

                    if (data.success) {
                        $modalInstance.close(data.object);
                    } else {
                        $scope.error = "Failure. Message was : " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.loading = false;
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };
});
