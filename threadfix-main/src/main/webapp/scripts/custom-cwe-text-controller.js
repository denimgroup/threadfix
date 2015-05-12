var module = angular.module('threadfix');

module.controller('CustomCweTextController', function($scope, $http, $modal, $log, tfEncoder, threadFixModalService){

    $scope.customCweTextList = [];

    var compare = function(a, b){
        return a.genericVulnerability.name.localeCompare(b.genericVulnerability.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/customCweText/info')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.customCweTextList = data.object.customCweTextList;
                    $scope.genericVulnerabilities = data.object.genericVulnerabilities;

                    if ($scope.customCweTextList.length === 0) {
                        $scope.customCweTextList = undefined;
                    } else {
                        $scope.customCweTextList.sort(compare);
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
            templateUrl: 'newCustomCweTextModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/customCweText/new");
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

        modalInstance.result.then(function (newCustomCweText) {

            if (!$scope.customCweTextList) {
                $scope.customCweTextList = [];
            }

            $scope.customCweTextList.push(newCustomCweText);

            $scope.customCweTextList.sort(compare);

            $scope.successMessage = "Successfully set custom text ";

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openEditModal = function(customCweText) {
        var modalInstance = $modal.open({
            windowClass: 'mapping-filter-modal',
            templateUrl: 'editCustomCweTextModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/customCweText/" + customCweText.id + "/edit");
                },
                object: function() {
                    var customCweTextCopy = angular.copy(customCweText);
                    return customCweTextCopy;
                },
                buttonText: function() {
                    return "Save Edits";
                },
                config: function() {
                    return {
                        genericVulnerabilities: $scope.genericVulnerabilities
                    };
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/customCweText/" + customCweText.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedCustomCweText) {

            if (editedCustomCweText) {
                threadFixModalService.deleteElement($scope.customCweTextList, customCweText);
                threadFixModalService.addElement($scope.customCweTextList, editedCustomCweText);

                $scope.successMessage = "Successfully set custom text.";
                $scope.customCweTextList.sort(compare);
            } else {

                threadFixModalService.deleteElement($scope.customCweTextList, customCweText);
                $scope.empty = $scope.customCweTextList.length === 0 || $scope.customCweTextList == undefined;
                $scope.successMessage = "Custom text was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };
});