var module = angular.module('threadfix')

module.controller('ApiKeysController', function($scope, $http, $modal, $log, tfEncoder, threadFixModalService){

    $scope.keys = [];

    var keyCompare = function(a,b) {
        return a.apiKey.localeCompare(b.apiKey);
    };

    // TODO move to service
    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/keys/list')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.keys = data.object.keys.filter(function(object) { return object.active && (!object.user || object.user.active); });
                    $scope.users = data.object.users;

                    if ($scope.keys.length === 0) {
                        $scope.keys = undefined;
                    } else {
                        $scope.keys.sort(keyCompare);
                    }
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newKeyModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/keys/new");
                },
                config: function() {
                    return {users: $scope.users};
                },
                object: function() {
                    return {};
                },
                buttonText: function() {
                    return "Create Key";
                }
            }
        });

        modalInstance.result.then(function (newKey) {

            if (!$scope.keys) {
                $scope.keys = [];
            }

            $scope.keys.push(newKey);

            $scope.keys.sort(keyCompare);

            $scope.successMessage = "Successfully created key " + newKey.apiKey;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openEditModal = function(key) {
        var modalInstance = $modal.open({
            templateUrl: 'editKeyModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/keys/" + key.id + "/edit");
                },
                object: function() {
                    var keyCopy = angular.copy(key);
                    return keyCopy;
                },
                buttonText: function() {
                    return "Save Edits";
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/keys/" + key.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedKey) {

            if (editedKey) {
                threadFixModalService.deleteElement($scope.keys, key);
                threadFixModalService.addElement($scope.keys, editedKey);

                $scope.successMessage = "Successfully edited key " + editedKey.apiKey;
                $scope.keys.sort(keyCompare);
            } else {
                threadFixModalService.deleteElement($scope.keys, key);
                $scope.successMessage = "API key was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

});