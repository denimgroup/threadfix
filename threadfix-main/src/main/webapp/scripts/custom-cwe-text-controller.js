var module = angular.module('threadfix');

module.controller('CustomCweTextController', function($scope, $http, $modal, $log, tfEncoder, threadFixModalService){

    $scope.genericVulnerabilitiesWithCustomText = [];

    var compare = function(a, b){
        return a.genericVulnerability.name.localeCompare(b.genericVulnerability.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/customCweText/info')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.genericVulnerabilitiesWithCustomText = data.object.genericVulnerabilitiesWithCustomText;
                    $scope.genericVulnerabilities = data.object.genericVulnerabilities;

                    if ($scope.genericVulnerabilitiesWithCustomText.length === 0) {
                        $scope.genericVulnerabilitiesWithCustomText = undefined;
                    } else {
                        $scope.genericVulnerabilitiesWithCustomText.sort(compare);
                    }
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve custom CWE text list. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            windowClass: 'mapping-filter-modal',
            templateUrl: 'customCweTextModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/customCweText/submit");
                },
                object: function() {
                    return {};
                },
                config: function() {
                    return {
                        genericVulnerabilities: $scope.genericVulnerabilities
                    };
                },
                buttonText: function() {
                    return "Set Custom Text";
                }
            }
        });

        modalInstance.result.then(function (newGenericVulnerability) {

            if (!$scope.genericVulnerabilitiesWithCustomText) {
                $scope.genericVulnerabilitiesWithCustomText = [];
            }

            $scope.genericVulnerabilitiesWithCustomText.push(newGenericVulnerability);

            $scope.genericVulnerabilitiesWithCustomText.sort(compare);

            $scope.successMessage = "Successfully set custom text ";

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openEditModal = function(genericVulnerability) {
        var modalInstance = $modal.open({
            windowClass: 'mapping-filter-modal',
            templateUrl: 'customCweTextModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/customCweText/submit");
                },
                object: function() {
                    var genericVulnerabilityCopy = angular.copy(genericVulnerability);
                    return genericVulnerabilityCopy;
                },
                buttonText: function() {
                    return "Set Custom Text";
                },
                config: function() {
                    return {
                        genericVulnerabilities: $scope.genericVulnerabilities
                    };
                }
            }
        });

        modalInstance.result.then(function (editedGenericVulnerability) {

            if (editedGenericVulnerability) {
                threadFixModalService.deleteElement($scope.genericVulnerabilitiesWithCustomText, genericVulnerability);
                threadFixModalService.addElement($scope.genericVulnerabilitiesWithCustomText, editedGenericVulnerability);

                $scope.successMessage = "Successfully set custom text.";
                $scope.genericVulnerabilitiesWithCustomText.sort(compare);
            } else {

                threadFixModalService.deleteElement($scope.genericVulnerabilitiesWithCustomText, genericVulnerability);
                $scope.empty = $scope.genericVulnerabilitiesWithCustomText.length === 0 || $scope.genericVulnerabilitiesWithCustomText == undefined;
                $scope.successMessage = "Custom text was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };
});