var myAppModule = angular.module('threadfix')



myAppModule.controller('GraphConfigModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, url, buttonText, deleteUrl, timeoutService) {

    $scope.object = object;
    $scope.config = config;
    $scope.buttonText = buttonText;
    $scope.loading = false;

    $scope.ok = function (valid) {

        if (valid) {
            timeoutService.timeout();
            $scope.loading = true;
            angular.forEach($scope.object, function(value){
                threadFixModalService.post(url, value).
                    success(function(data, status, headers, config) {
                        timeoutService.cancel();

                    $scope.loading = false;

                    if (data.success) {
                        $modalInstance.close(data.object);
                    } else {
                        if (data.errorMap) {
                            for (var index in data.errorMap) {
                                if (data.errorMap.hasOwnProperty(index)) {

                                    if (data.errorMap[index] === 'errors.self.certificate') {
                                        $scope.showKeytoolLink = true;
                                    } else {
                                        $scope.object[index + "_error"] = data.errorMap[index];
                                    }
                                }
                            }
                        } else {
                            $scope.error = "Failure. Message was : " + data.message;
                        }
                    }
                }).
                error(function(data, status, headers, config) {
                    timeoutService.cancel();
                    $scope.loading = false;
                    $scope.error = "Failure. HTTP status was " + status;
                });
            });
        }
        $rootScope.$broadcast('vulnChanged', null);
    };

    $scope.ind = 0;
    $scope.setCurrentIndex = function(indx){
        $scope.ind = indx;
    }

    $scope.getCurrentIndex = function(){

        return $scope.ind;
    }

    $scope.focusInput = true;

    $scope.switchTo = function(name) {
        $rootScope.$broadcast('modalSwitch', name);
    }

    $scope.cancel = function () {
        timeoutService.cancel();
        $modalInstance.dismiss('cancel');
    };
});



