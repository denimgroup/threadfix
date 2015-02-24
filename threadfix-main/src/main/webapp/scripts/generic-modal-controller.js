var myAppModule = angular.module('threadfix')

// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);


myAppModule.controller('GenericModalController', function ($scope, $modalInstance, $http, threadFixModalService, object, url, buttonText, deleteUrl) {

    $scope.object = object;

    $scope.buttonText = buttonText;

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
                        $scope.error = "Failure: " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.loading = false;
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.focusInput = true;

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };

    $scope.showDeleteDialog = function(itemName) {
        if (confirm("Are you sure you want to delete this " + itemName + "?")) {
            $http.post(deleteUrl).
                success(function(data, status, headers, config) {
                    $modalInstance.close(false);
                }).
                error(function(data, status, headers, config) {
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };
});
