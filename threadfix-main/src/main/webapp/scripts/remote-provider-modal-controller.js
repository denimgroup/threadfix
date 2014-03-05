var myAppModule = angular.module('threadfix')

myAppModule.controller('RemoteProviderModalController', function ($scope, $modalInstance, $http, threadFixModalService, type, url) {

    $scope.object = type;

    $scope.initialUsername = type.username;
    $scope.initialApiKey   = type.apiKey;

    $scope.buttonText = "Save";

    $scope.loading = false;

    $scope.ok = function (valid) {

        if (valid) {

            var confirmed = true;

            if ($scope.initialUsername && $scope.initialUsername !== $scope.object.username) {
                confirmed = confirm("Warning: You have changed your username, all existing " + type.name + " apps will be deleted.");
            }

            if ($scope.initialApiKey && $scope.initialApiKey !== $scope.object.apiKey) {
                confirmed = confirm("Warning: You have changed your API key, all existing " + type.name + " apps will be deleted.");
            }

            if (confirmed) {
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
        }
    };

    $scope.focusInput = true;

    $scope.cancel = function () {

        $scope.object.apiKey = $scope.initialApiKey;
        $scope.object.username = $scope.initialUsername;


        $modalInstance.dismiss('cancel');
    };
});
