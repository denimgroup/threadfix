var myAppModule = angular.module('threadfix')

myAppModule.controller('AddDefectTrackerModalController', function ($scope, $http, $rootScope, $modalInstance, tfEncoder, threadFixModalService, object, config) {

    $scope.object = object;

    $scope.config = config;

    $scope.loading = false;

    $scope.getProductNames = function() {

        var app = $scope.config.application;
        var url = tfEncoder.encode("/organizations/" + app.team.id + "/applications/jsontest");

        $http.post(url, $scope.object).
            success(function(data, status, headers, config) {
                $scope.loading = false;

                if (data.success) {
                    $scope.productNames = data.object;
                } else {
                    $scope.error = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.loading = false;
                $scope.error = "Failure. HTTP status was " + status;
            });
    }

    $scope.ok = function (valid) {

        if (valid) {
            $scope.loading = true;

            var app = $scope.config.application;
            var url = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/edit/addDTAjax");

            $scope.object.defectTracker = {
                id: $scope.object.defectTrackerId
            }

            threadFixModalService.post(url, $scope.object).
                success(function(data, status, headers, config) {
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
                    $scope.loading = false;
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.focusInput = true;

    $scope.switchTo = function(name) {
        $rootScope.$broadcast('modalSwitch', name);
    }

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };
});
