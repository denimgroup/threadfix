var module = angular.module('threadfix');

module.controller("UserPermissionsConfigController", function($scope, $http, $modal, $log, tfEncoder){

    $scope.keys = [];

    var keyCompare = function(a,b) {
        return a.apiKey.localeCompare(b.apiKey);
    };

    var defaultTeam = { id: 0, name: 'Select a Team'};

    // TODO move to service
    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/users/' + $scope.userId + '/permissions/map')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.maps = data.object.maps;
                    $scope.teams = data.object.teams;
                    $scope.roles = data.object.roles;

                    $scope.teams.push(defaultTeam);

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

    $scope.openAddPermissionsModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'permissionForm.html',
            controller: 'PermissionModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/users/" + $scope.userId + "/access/new");
                },
                object: function() {
                    return {
                        team: defaultTeam,
                        allApps: true,
                        application: {
                            id: 0
                        }, role: {
                            id: 0
                        }
                    };
                },
                buttonText: function() {
                    return "Save Map";
                },
                config: function() {
                    return {
                        teams: $scope.teams,
                        roles: $scope.roles
                    };
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
    }

    $scope.edit = function(key) {
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
                $scope.successMessage = "Successfully edited key " + editedKey.apiKey;
                $scope.keys.sort(keyCompare);
            } else {
                var index = $scope.keys.indexOf(key);

                if (index > -1) {
                    $scope.keys.splice(index, 1);
                }

                if ($scope.keys.length === 0) {
                    $scope.keys = undefined;
                }
                $scope.successMessage = "API key was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.delete = function(map) {
        // TODO yo
    }

});