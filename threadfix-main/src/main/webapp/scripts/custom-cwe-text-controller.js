var module = angular.module('threadfix');

module.controller('CustomCweTextController', function($scope, $http, $modal, $log, tfEncoder, threadFixModalService){

    $scope.genericVulnerabilitiesWithCustomText = [];
    $scope.genericVulnerabilities = [];

    var compare = function(a, b){
        return a.cweId - b.cweId;
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
                        genericVulnerabilities: $scope.genericVulnerabilities,
                        edit: false
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
            removeGenericVulnerability($scope.genericVulnerabilities, newGenericVulnerability);

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
                    genericVulnerabilityCopy.name = genericVulnerabilityCopy.name + ' (CWE ' + genericVulnerabilityCopy.cweId + ')';
                    return genericVulnerabilityCopy;
                },
                buttonText: function() {
                    return "Set Custom Text";
                },
                config: function() {
                    return {
                        genericVulnerabilities: $scope.genericVulnerabilities,
                        edit: true
                    };
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/customCweText/" + genericVulnerability.id + "/delete");
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
                threadFixModalService.addElement($scope.genericVulnerabilities, genericVulnerability);
                $scope.genericVulnerabilities.sort(compare);
                $scope.empty = $scope.genericVulnerabilitiesWithCustomText.length === 0 || $scope.genericVulnerabilitiesWithCustomText == undefined;
                $scope.successMessage = "Custom text was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };
});

function removeGenericVulnerability(list, genericVulnerability){
    var index = -1;

    for(var i = 0; i < list.length; i++){
        if(list[i].id == genericVulnerability.id){
            index = i;
        }
    }

    if(index > -1){
        list.splice(index, 1);
    }

    if (list.length === 0) {
        list = undefined;
    }
}