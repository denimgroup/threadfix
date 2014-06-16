var myAppModule = angular.module('threadfix')

// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);


myAppModule.controller('UserPageController', function ($scope, $modal, $http, $log, tfEncoder) {

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    var reloadList = function() {
        $scope.initialized = false;

        $http.get(tfEncoder.encode('/configuration/users/map')).
            success(function(data, status, headers, config) {

                if (data.success) {

                    if (data.object.users.length > 0) {
                        $scope.users = data.object.users;
                        $scope.roles = data.object.roles;
                        $scope.users.sort(nameCompare);
                    }

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve user list. HTTP status was " + status;
            });
    }

    $scope.$on('rootScopeInitialized', function() {
        reloadList();
    });

    $scope.goToEditPermissionsPage = function(user) {
        window.location.href = tfEncoder.encode("/configuration/users/" + user.id + "/permissions");
    }

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'userForm.html',
            controller: 'UserModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/users/new");
                },
                user: function() {
                    return {};
                },
                roles: function() {
                    return $scope.roles
                }
            }
        });

        modalInstance.result.then(function (newUser) {
            reloadList();

            $scope.successMessage = "Successfully created user " + newUser.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openEditModal = function(user) {
        var modalInstance = $modal.open({
            templateUrl: 'editUserForm.html',
            controller: 'UserModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/users/" + user.id + "/edit");
                },
                user: function() {
                    var userCopy = angular.copy(user);
                    return userCopy;
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/users/" + user.id + "/delete");
                },
                roles: function() {
                    return $scope.roles
                }
            }
        });

        modalInstance.result.then(function (editedUser) {

            if (editedUser) {
                reloadList();
                $scope.successMessage = "Successfully edited user " + editedUser.name;
            } else {
                $scope.successMessage = "Successfully deleted user " + user.name;
                reloadList();
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

});
