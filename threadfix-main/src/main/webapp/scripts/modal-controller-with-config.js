var myAppModule = angular.module('threadfix');


// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);

// TODO wrap this back into genericModalController and make config optional

myAppModule.controller('ModalControllerWithConfig', function ($log, $scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, url, buttonText, deleteUrl, timeoutService, tfEncoder) {

    $scope.object = object;

    $scope.config = config;

    $scope.buttonText = buttonText;

    $scope.loading = false;

    $scope.ok = function (valid) {

        if (valid) {
            timeoutService.timeout();
            $scope.loading = true;

            threadFixModalService.post(url, $scope.object).
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
        }
    };

    $scope.focusInput = true;

    $scope.switchTo = function(name) {
        $rootScope.$broadcast('modalSwitch', name);
    };

    $scope.cancel = function () {
        timeoutService.cancel();
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

    $scope.loadTagsList = function() {
        $http.get(tfEncoder.encode('/configuration/tags/map')).
            success(function(data) {
                if (data.success) {
                    if (data.object.tags.length > 0) {
                        $scope.tags = data.object.tags;
                        $scope.tags.sort(function(a,b) {
                            return a.name.localeCompare(b.name);
                        });
                    } else $scope.tags = [];
                } else {
                    $log.warn("Failure. Message was : " + data.message);
                }
            }).
            error(function(data, status, headers, config) {
                $scope.tags = [];
                $log.warn("Failed to retrieve waf list. HTTP status was " + status);
            });
    }

});
