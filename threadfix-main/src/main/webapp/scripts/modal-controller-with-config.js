var myAppModule = angular.module('threadfix');


// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);
myAppModule.value('returnFullResponse', false);

// TODO wrap this back into genericModalController and make config optional

myAppModule.controller('ModalControllerWithConfig', function ($log, $scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, url, buttonText, deleteUrl, timeoutService, tfEncoder, returnFullResponse) {

    $scope.object = object;

    $scope.config = config;

    $scope.buttonText = buttonText;

    $scope.loading = false;

    var currentErrors = [];

    $scope.ok = function (valid) {

        if (valid) {
            timeoutService.timeout();
            $scope.loading = true;

            threadFixModalService.post(url, $scope.object).
                //$http.post(url, $scope.object).
                success(function(data, status, headers, config) {
                    timeoutService.cancel();
                    $scope.loading = false;

                    if (data.success) {
                        if (returnFullResponse) {
                            $modalInstance.close(data);
                        } else {
                            $modalInstance.close(data.object);
                        }
                    } else {
                        if (data.errorMap) {

                            // this code will clear out previous errors
                            currentErrors.forEach(function(errorKey) {
                                $scope.object[errorKey] = undefined;
                            });

                            currentErrors = [];

                            for (var index in data.errorMap) {
                                if (data.errorMap.hasOwnProperty(index)) {

                                    if (data.errorMap[index] === 'errors.self.certificate') {
                                        $scope.showKeytoolLink = true;
                                    } else {
                                        currentErrors.push(index + "_error");
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
                    $scope.error = "Failure. " + (data && data.message ? "Message was " + data.message : "") + ". HTTP status was " + status;
                });
        }
    };

    $scope.focusInput = true;

    $scope.switchTo = function(name) {
        $rootScope.$broadcast('modalSwitch', name, $scope.object);
    };

    $scope.cancel = function () {
        timeoutService.cancel();
        $modalInstance.dismiss('cancel');
    };

    $scope.showDeleteDialog = function(itemName) {
        if (confirm("Are you sure you want to delete this " + itemName + "?")) {
            $http.post(deleteUrl).
                success(function(data, status, headers, config) {

                    if (returnFullResponse) {
                        data.delete = true;
                        $modalInstance.close(data);
                    } else {
                        $modalInstance.close(false);
                    }

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
    };

    $scope.startsWith = function(vulnerability, viewValue) {
        return vulnerability.substr(0, viewValue.length).toLowerCase() == viewValue.toLowerCase();
    };

    $scope.orderByStartsWithFirst = function(propertyName, $viewValue) {
        return function(object) {
            var weight = 2147483647;
            if (object[propertyName]) {
                var lowerName = (object[propertyName] + "").toLowerCase();
                var indexOf = lowerName.indexOf(($viewValue + "").toLowerCase());
                if (indexOf >= 0) {
                    weight = indexOf;
                } else {
                    weight = 2147483646;
                }
            }
            return weight;
        }
    };

    $scope.convertDateAndSubmit = function(valid) {
        if (valid) {
            $scope.object.date = new Date($scope.object.date);
            $scope.object.date = $scope.object.date.getTime();
            $scope.ok(valid);
        }
    }


});
