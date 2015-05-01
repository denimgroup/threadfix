var myAppModule = angular.module('threadfix')

// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);


myAppModule.controller('UserPageController', function ($scope, $modal, $http, $log, $rootScope, tfEncoder) {

    ////////////////////////////////////////////////////////////////////////////////
    //             Basic Page Functionality + $on(rootScopeInitialized)
    ////////////////////////////////////////////////////////////////////////////////

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.numberToShow = 50;

    var reloadList = function(callBack) {
        $scope.initialized = false;

        $http.get(tfEncoder.encode('/configuration/users/map/page/' + $scope.page + '/' + $scope.numberToShow)).
            success(function(data) {

                if (data.success) {
                    $scope.countUsers = data.object.countUsers;
                    if (data.object.users.length > 0) {
                        $scope.users = data.object.users;
                        $scope.roles = data.object.roles;
                        $scope.users.sort(nameCompare);

                        $scope.teams = data.object.teams;
                        $scope.teams.sort(nameCompare);

                        $scope.teams.forEach(function(team) {
                            team.applications.sort(nameCompare);
                        });

                        $rootScope.$broadcast("teams", $scope.teams);
                        $rootScope.$broadcast("roles", $scope.roles);

                        // allow undefined
                        callBack && callBack();

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

    ////////////////////////////////////////////////////////////////////////////////
    //                              New User Modal
    ////////////////////////////////////////////////////////////////////////////////

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
            reloadList(function() {
                selectUserWithId(newUser.id);
            });

            $scope.successMessage = "Successfully created user " + newUser.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    ////////////////////////////////////////////////////////////////////////////////
    //                     Setting current user + updating data
    ////////////////////////////////////////////////////////////////////////////////

    var addMapsToUser = function(user, callback) {

        // if there are no roles, we shouldn't try to get permissions.
        if (!$scope.roles) {
            callback && callback();
            return;
        }

        $http.get(tfEncoder.encode('/configuration/users/' + user.id + '/permissions/map')).
            success(function(data) {

                if (data.success) {
                    user.maps = data.object.maps;

                    user.noTeamRoles = true;
                    user.noApplicationRoles = true;

                    user.maps.forEach(function(map) {
                        if (map.allApps) {
                            user.noTeamRoles = false;
                        } else {
                            user.noApplicationRoles = false;
                        }
                    });

                    callback && callback();
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    };

    $scope.clearMessage = function() {
        $scope.successMessage = undefined;
    };

    $scope.updatePage = function(page) {
        $scope.page = page;
        reloadList();
    };

    $scope.setCurrentUser = function(user) {
        if (user.wasSelected) {
            $scope.currentUser = user.formUser;
        } else {
            $scope.currentUser = angular.copy(user);
            addMapsToUser($scope.currentUser, function() {
                user.formUser = $scope.currentUser;
                if (!$scope.currentUser.hasGlobalGroupAccess) {
                    $scope.currentUser.globalRole = { id: "-1"};
                } else if (!$scope.currentUser.globalRole) {
                    $scope.currentUser.globalRole = { id: "0" };
                } else {
                    $scope.currentUser.globalRole.id = "" + $scope.currentUser.globalRole.id;
                }
                if (!$scope.currentUser.displayName) {
                    $scope.currentUser.displayName = "";
                }
                $scope.currentUser.unencryptedPassword = "";
                $scope.currentUser.passwordConfirm = "";
                user.baseUser = angular.copy($scope.currentUser);
            });
            user.wasSelected = true;
        }
        $scope.userId = $scope.currentUser.id;
    };

    $scope.compare = function(form, user) {
        return !form.$dirty || form.$invalid || angular.equals($scope.currentUser, user.baseUser)
    };

    function selectUserWithId(targetId) {
        var index = 0, targetIndex = -1;
        $scope.users.forEach(function (listUser) {
            if (listUser.id === targetId) {
                targetIndex = index;
            }
            index = index + 1;
        });

        $scope.setCurrentUser($scope.users[targetIndex]);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                              Update (Save Edits)
    ////////////////////////////////////////////////////////////////////////////////

    $scope.submitUpdate = function(valid) {
        if (!valid) {
            return;
        }

        $scope.currentUser.hasGlobalGroupAccess = $scope.currentUser.globalRole.id != -1;

        $http.post(tfEncoder.encode("/configuration/users/" + $scope.currentUser.id + "/edit"), $scope.currentUser).
            success(function(data) {

                if (data.success) {
                    $scope.successMessage = "Edit succeeded.";

                    $scope.users = data.object;

                    selectUserWithId($scope.currentUser.id);
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve user list. HTTP status was " + status;
            });
    };

    ////////////////////////////////////////////////////////////////////////////////
    //                            New Permissions Modals
    ////////////////////////////////////////////////////////////////////////////////

    $scope.openAddApplicationPermissionsModal = function() {
        openPermissionsModal(false);
    };

    $scope.openAddTeamPermissionsModal = function() {
        openPermissionsModal(true);
    };

    var openPermissionsModal = function(allApps) {

        if ($scope.teams.length) {
            var modalInstance = $modal.open({
                templateUrl: 'permissionForm.html',
                controller: 'PermissionModalController',
                resolve: {
                    url: function () {
                        return tfEncoder.encode("/configuration/users/" + $scope.currentUser.id + "/access/new");
                    },
                    object: function () {
                        return {
                            team: $scope.teams[0],
                            allApps: allApps,
                            application: {
                                id: 0
                            }, role: {
                                id: 0
                            }
                        };
                    },
                    buttonText: function () {
                        return "Save Map";
                    },
                    config: function () {
                        return {
                            teams: $scope.teams,
                            roles: $scope.roles
                        };
                    },
                    headerText: function () {
                        return allApps ? "Add Team Permission" : "Add Application Permissions";
                    }
                }
            });

            modalInstance.result.then(function (permissions) {

                addMapsToUser($scope.currentUser);

                $scope.successMessage = "Successfully added permissions.";

            }, function () {
                $log.info('Modal dismissed at: ' + new Date());
            });

        }

    };

    ////////////////////////////////////////////////////////////////////////////////
    //                            Editing
    ////////////////////////////////////////////////////////////////////////////////

    // TODO clean this up
    var doLookups = function(perms) {

        var lastTeam = undefined;
        var lastRole = undefined;

        $scope.teams.forEach(function(team) {
            if (team.id === perms.organization.id) {
                lastTeam = team;
            }
        });

        if (perms.role) {
            $scope.roles.forEach(function(role) {
                if (role.id === perms.role.id) {
                    lastRole = role;
                }
            });
        }

        perms.role = lastRole;
        perms.team = lastTeam;
        var appList = lastTeam.applications;

        var appMaps = perms.accessControlApplicationMaps;

        appMaps.forEach(function(map) {
            appList.forEach(function(app) {
                if (map.role.id !== 0 && app.id === map.application.id) {
                    app.role = { id: map.role.id };
                }
            });
        });

        appList.forEach(function(app) {
            if (!app.role) {
                app.role = { id: 0 };
            }
        });

        return appList;
    };

    $scope.edit = function(permObject) {

        var apps = doLookups(permObject);

        var modalInstance = $modal.open({
            templateUrl: 'permissionForm.html',
            controller: 'PermissionModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/users/" + $scope.userId + "/access/" + permObject.id + "/edit");
                },
                object: function() {
                    return permObject;
                },
                buttonText: function() {
                    return "Save Edits";
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/users/" + $scope.userId + "/access/" + permObject.id + "/delete");
                },
                config: function() {
                    return {
                        teams: $scope.teams,
                        roles: $scope.roles,
                        appList: apps
                    };
                },
                headerText: function() {
                    return "Edit Permissions Mapping";
                }
            }
        });

        modalInstance.result.then(function (editedPermissionsObject) {

            addMapsToUser($scope.currentUser);

            if (editedPermissionsObject) {
                $scope.successMessage = "Successfully edited permissions.";
            } else {
                $scope.successMessage = "Permissions object was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    ////////////////////////////////////////////////////////////////////////////////
    //                            Deletion
    ////////////////////////////////////////////////////////////////////////////////

    $scope.deleteUser = function() {
        if (confirm("Are you sure you want to delete this user?")) {
            $http.post(tfEncoder.encode('/configuration/users/' + $scope.userId + '/delete')).
                success(function(data, status, headers, config) {
                    if (data.success) {
                        // this will cause the user to be logged out if the session is invalid
                        reloadList();
                        $scope.successMessage = "User was successfully deleted.";
                    } else {
                        $scope.errorMessage = "Failure: " + data.message;
                    }

                    $scope.initialized = true;
                }).
                error(function(data, status, headers, config) {
                    $scope.initialized = true;
                    $scope.errorMessage = "Failed to delete. HTTP status was " + status;
                });
        }
    };

    var makeDeleteRequest = function(url) {
        if (confirm("Are you sure you want to delete this user?")) {
            $http.post(tfEncoder.encode('/configuration/users/' + $scope.userId + url)).
                success(function(data, status, headers, config) {
                    if (data.success) {
                        addMapsToUser($scope.currentUser);
                        $scope.successMessage = "Permission was successfully deleted.";
                    } else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }

                    $scope.initialized = true;
                }).
                error(function(data, status, headers, config) {
                    $scope.initialized = true;
                    $scope.errorMessage = "Failed to delete permission. HTTP status was " + status;
                });
        }
    };

    $scope.deleteApp = function(map) {
        makeDeleteRequest('/access/app/' + map.id + '/delete')
    };

    $scope.deleteTeam = function(map) {
        makeDeleteRequest('/access/team/' + map.id + '/delete')
    };

    $scope.$on('reloadRoles', function() {
        reloadList(function() {
            selectUserWithId($scope.userId);
        });
    });

});
