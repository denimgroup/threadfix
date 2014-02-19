var myAppModule = angular.module('threadfix')

myAppModule.controller('GenericModalController', function ($scope, $modalInstance, threadFixModalService, object, url) {

    $scope.object = object;

    $scope.loading = false;

    $scope.ok = function (valid) {

        if (valid) {
            $scope.loading = true;

            threadFixModalService.post(url, $scope.object).
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
