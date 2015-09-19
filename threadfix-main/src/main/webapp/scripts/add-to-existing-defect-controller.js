var myAppModule = angular.module('threadfix');

myAppModule.controller('AddToExistingDefectController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, configUrl, url, timeoutService) {

    $scope.focusInput = true;

    $scope.object = object;
    $scope.isDynamicForm = false;
    $scope.hasFields = true;

    $scope.config = config;
    $scope.config.defects = [{ name: ''}];

    $scope.initialized = true;
    $scope.loadingDefectIds = true;
    $scope.vulns = config.vulns;

    $scope.showRemoveLink = $scope.vulns.length > 1;

    timeoutService.timeout();

    $http.get(configUrl).
        success(function(data, status, headers, config) {
            $scope.initialized = true;
            timeoutService.cancel();

            if (data.success) {
                $scope.config.defects = data.object.defectList;

                $scope.config.placeholder = "Enter "
                    + (data.object.defectTrackerName == null ? "defect" : data.object.defectTrackerName)
                    + " id.";

                if ($scope.config.defects && $scope.config.defects.length > 0) {
                    $scope.config.placeholder += " Example, " + $scope.config.defects[0];
                }

            } else {

                // setting these two booleans will hide the form.
                $scope.hasFields = false;
                $scope.isDynamicForm = true;

                $scope.errorMessage = data.message;
            }
            $scope.loadingDefectIds = false;
        }).
        error(function(data, status, headers, config) {
            timeoutService.cancel();
            $scope.initialized = true;
            $scope.errorMessage = "Failure. HTTP status was " + status;
        });


    $scope.ok = function (form) {

        if (form.$valid) {
            timeoutService.timeout();
            $scope.loading = true;

            $scope.object.vulnerabilityIds = $scope.vulns.map(function(vuln) {
                return vuln.id;
            });

            $scope.object.fieldsMapStr = JSON.stringify($scope.fieldsMap);
            threadFixModalService.post(url, $scope.object).
                success(function(data, status, headers, config) {
                    timeoutService.cancel();
                    $scope.loading = false;

                    if (data.success) {
                        $modalInstance.close(data.object);
                    } else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    timeoutService.cancel();
                    $scope.loading = false;
                    $scope.errorMessage = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.cancel = function () {
        timeoutService.cancel();
        $modalInstance.dismiss('cancel');
    };

    $scope.remove = function(vuln) {
        var index = $scope.vulns.indexOf(vuln);

        if (index > -1) {
            $scope.vulns.splice(index, 1);
        }

        $scope.showRemoveLink = $scope.vulns.length > 1;
    };

    $scope.emptyMultiChoice = function(path) {
        var field = $scope.fieldsMap[path];

        if (field.length === 1 && field[0] === "") {
            delete $scope.fieldsMap[path];
        }
    };

    $scope.checkAndReset = function(pathSegment1, pathSegment2) {
        if (!$scope.fieldsMap[pathSegment1][pathSegment2]) {
            delete $scope.fieldsMap[pathSegment1][pathSegment2];
        }

        $scope.requiredErrorMap[pathSegment1] = Object.keys($scope.fieldsMap[pathSegment1]).length === 0;
    };

    $scope.requiredErrorMap = {}
});
