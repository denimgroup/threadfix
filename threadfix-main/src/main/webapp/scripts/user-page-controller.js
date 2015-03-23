var myAppModule = angular.module('threadfix')

// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);


myAppModule.controller('UserPageController', function ($scope, $modal, $http, $log, tfEncoder) {

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.numberToShow = 50;

    var reloadList = function() {
        $scope.initialized = false;

        $http.get(tfEncoder.encode('/configuration/users/map/page/' + $scope.page + '/' + $scope.numberToShow)).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.countUsers = data.object.countUsers;
                    if (data.object.users.length > 0) {
                        $scope.users = data.object.users;
                        $scope.roles = data.object.roles;
                        $scope.users.sort(nameCompare);
                    } else {

                        // If the last page is no longer exist then refresh to page 1
                        if ($scope.page !== 1) {
                            $scope.page = 1;
                            reloadList();
                        }
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
    };

    $scope.$on('rootScopeInitialized', function() {
        $scope.page = 1;
        reloadList();
    });

    $scope.goToEditPermissionsPage = function(user) {
        window.location.href = tfEncoder.encode("/configuration/users/" + user.id + "/permissions");
    };

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
    };

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

                    if (!userCopy.globalRole) {
                        userCopy.globalRole = { id: 0 };
                    }

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

        modalInstance.result.then(function (editedUserName) {

            if (editedUserName) {
                reloadList();
                $scope.successMessage = "Successfully edited user " + editedUserName;
            } else {
                $scope.successMessage = "Successfully deleted user " + user.name;
                reloadList();
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.updatePage = function(page) {
        $scope.page = page;
        reloadList();
    }

});
