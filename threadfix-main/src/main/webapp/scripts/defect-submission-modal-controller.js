var myAppModule = angular.module('threadfix')

// TODO wrap this back into genericModalController and make config optional
myAppModule.controller('DefectSubmissionModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, object, config, configUrl, url) {

    $scope.focusInput = true;

    $scope.object = object;

    $scope.config = config;

    $scope.initialized = false;
    $scope.vulns = config.vulns;

    $scope.showRemoveLink = $scope.vulns.length > 1;

    $http.get(configUrl).
        success(function(data, status, headers, config) {
            $scope.initialized = true;

            if (data.success) {
                $scope.config = data.object.projectMetadata;
                $scope.config.defectTrackerName = data.object.defectTrackerName;

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
            $scope.loading = true;

            $scope.object.vulnerabilityIds = $scope.vulns.map(function(vuln) {
                return vuln.id;
            });

            threadFixModalService.post(url, $scope.object).
                success(function(data, status, headers, config) {
                    $scope.loading = false;

                    if (data.success) {
                        $modalInstance.close(data.object);
                    } else {
                        $scope.errors = "Failure. Message was : " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.loading = false;
                    $scope.errors = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.cancel = function () {
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
