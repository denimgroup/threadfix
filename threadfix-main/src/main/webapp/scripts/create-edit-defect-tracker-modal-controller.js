var myAppModule = angular.module('threadfix');

myAppModule.controller('CreateEditDefectTrackerModalController', function ($q, $log, $scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, url, buttonText, deleteUrl, timeoutService, tfEncoder) {

    $scope.object = object;

    $scope.config = config;

    $scope.buttonText = buttonText;

    $scope.oldDefaultProduct = angular.copy($scope.object.defaultProductName);

    $scope.loading = false;

    var currentErrors = [];

    $scope.getProductNames = function() {
        $scope.loadingProductNames = true;

        var url = tfEncoder.encode("/configuration/defecttrackers/jsontest");

        timeoutService.timeout();

        $http.post(url, $scope.object).
            success(function(data, status, headers, config) {
                timeoutService.cancel();
                $scope.loadingProductNames = false;

                // this code will clear out previous errors
                currentErrors.forEach(function(errorKey) {
                    $scope.object[errorKey] = undefined;
                });

                currentErrors = [];

                if (data.success) {
                    $scope.productNames = data.object;
                    $scope.error = null;
                } else {
                    if (data.errorMap) {

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
                $scope.loadingProductNames = false;
                $scope.error = "Failure. " + (data && data.message ? "Message was " + data.message : "") + ". HTTP status was " + status;
            });
    };

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
                    $scope.error = "Failure. " + (data && data.message ? "Message was " + data.message : "") + ". HTTP status was " + status;
                });
        }
    };

    // Filter method is passed with attribute 'filter-list-method="method(userInput)"'.
    // Called on the onchange event from the input field. Should return a promise resolving with an array of items to show in the dropdown.
    // If no filter method is passed to the the directive, the default dropdown will show constantly.
    $scope.filterStringList = function(userInput) {
        var filter = $q.defer();
        var normalisedInput = userInput.toLowerCase();
        var filteredArray = [];

        if ($scope.productNames)
            filteredArray = $scope.productNames.filter(function(country) {
                return country.toLowerCase().indexOf(normalisedInput) >= 0;
            });

        filter.resolve(filteredArray);
        return filter.promise;
    };
});