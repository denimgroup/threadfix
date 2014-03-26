var module = angular.module('threadfix')

module.controller('ApiKeysController', function($scope, $http, $modal, $log, tfEncoder){

    $scope.keys = [];

    var keyCompare = function(a,b) {
        return a.apiKey.localeCompare(b.apiKey);
    };

    // TODO move to service
    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/keys/list')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.keys = data.object;

                    $scope.keys.sort(keyCompare);
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
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/keys/new");
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

            $scope.keys.push(newKey);

            $scope.keys.sort(keyCompare);

            $scope.successMessage = "Successfully created key " + newKey.apiKey;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openEditModal = function(key) {
        var modalInstance = $modal.open({
            templateUrl: 'editKeyModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/keys/" + key.id + "/edit");
                },
                object: function() {
                    return key;
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
                $scope.keys.sort(keyCompare);
            } else {
                var index = $scope.keys.indexOf(key);

                if (index > -1) {
                    $scope.keys.splice(index, 1);
                }
            }

            $scope.successMessage = "Successfully edited key " + editedKey.apiKey;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

});