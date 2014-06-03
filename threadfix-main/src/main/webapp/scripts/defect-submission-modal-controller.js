var myAppModule = angular.module('threadfix')

// TODO wrap this back into genericModalController and make config optional
myAppModule.controller('DefectSubmissionModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, configUrl, url, timeoutService) {

    $scope.focusInput = true;

    $scope.object = object;

    $scope.config = config;

    $scope.initialized = false;
    $scope.vulns = config.vulns;

    $scope.showRemoveLink = $scope.vulns.length > 1;

    timeoutService.timeout();

    $http.get(configUrl).
        success(function(data, status, headers, config) {
            $scope.initialized = true;

            if (data.success) {
                timeoutService.cancel();
                $scope.config = data.object.projectMetadata;
                $scope.config.typeName = data.object.defectTrackerName;
                $scope.config.defectTrackerName = data.object.defectTrackerName;

                $scope.config.defects = data.object.defectList.map(function(defect) {
                    return defect.nativeId;
                });

                $scope.object.id = $scope.config.defects[0];
                $scope.object.selectedComponent = $scope.config.components[0];
                $scope.object.priority = $scope.config.priorities[0];
                $scope.object.status = $scope.config.statuses[0];
                $scope.object.version = $scope.config.versions[0];
                $scope.object.severity = $scope.config.severities[0];
            } else {
                $scope.errorMessage = "Failure. Message was : " + data.message;
            }
        }).
        error(function(data, status, headers, config) {
            $scope.initialized = true;
            $scope.errorMessage = "Failure. HTTP status was " + status;
        });


    $scope.ok = function (valid) {

        if (valid) {
            timeoutService.timeout();
            $scope.loading = true;

            $scope.object.vulnerabilityIds = $scope.vulns.map(function(vuln) {
                return vuln.id;
            });

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

});
