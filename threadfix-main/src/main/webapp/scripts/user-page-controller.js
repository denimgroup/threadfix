var myAppModule = angular.module('threadfix');

// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);


myAppModule.controller('UserPageController', function ($scope, $modal, $http, $log, $rootScope, tfEncoder, threadFixModalService) {

    ////////////////////////////////////////////////////////////////////////////////
    //             Basic Page Functionality + $on(rootScopeInitialized)
    ////////////////////////////////////////////////////////////////////////////////

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    var lastSearchString = undefined;
    var lastNumber = 0;
    var lastPage = 0;

    $scope.activateTab = function(tab) {
        $scope.active = {}; //reset
        $scope.active[tab] = true;
        $rootScope.title = tab[0].toUpperCase() + tab.substr(1);
    };

    $scope.numberToShow = 20;

    var reloadList = function(callBack) {
        $scope.initialized = false;

        $http.get(tfEncoder.encode('/configuration/users/map/page/' + $scope.page + '/' + $scope.numberToShow)).
            success(function(data) {

                if (data.success) {
                    $scope.countUsers = data.object.countUsers;
                    if (data.object.users.length > 0) {
                        $scope.roles = data.object.roles;
                        $scope.users = data.object.users;

                        $scope.teams = data.object.teams;
                        $scope.teams.sort(nameCompare);

                        $scope.teams.forEach(function(team) {
                            team.applications.sort(nameCompare);
                        });

                        $rootScope.$broadcast("teams", $scope.teams);
                        $rootScope.$broadcast("roles", $scope.roles);

                        // allow undefined
                        if ($scope.userId) {
                            selectUserWithId($scope.userId);
                        }

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

    $scope.$on('refreshUsers', function() {
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
            $scope.userId = newUser.id;
            reloadList();

            $scope.usersSuccessMessage = "Successfully created user " + newUser.name;

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
        $scope.usersSuccessMessage = undefined;
    };

    $scope.updatePage = function(page, searchString) {
        $scope.page = page;
        $scope.searchUsers(searchString);
    };

    $scope.setCurrentUser = function(user) {
        if (user.wasSelected) {
            $scope.currentUser = user.formUser;
            $scope.currentUrl = "/configuration/users/" + $scope.currentUser.id;
            $rootScope.$broadcast('userSelected');
        } else {
            $scope.currentUser = angular.copy(user);
            $scope.currentUrl = "/configuration/users/" + $scope.currentUser.id;
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
                $rootScope.$broadcast('userSelected');
            });
            user.wasSelected = true;
        }
        $scope.userId = $scope.currentUser.id;
    };

    $scope.compare = function(form, user) {
        return !form.$dirty || form.$invalid || angular.equals($scope.currentUser, user.baseUser)
    };

    $scope.selectUser = function(user) {
        selectUserWithId(user.id);
    };

    $scope.searchUsers = function(searchText) {

        if (lastSearchString && lastSearchString === searchText &&
                lastNumber === $scope.numberToShow &&
                lastPage === $scope.page) {
            return;
        }

        var users = [];

        var searchObject = {
            "searchString" : searchText,
            "page" : $scope.page,
            "number" : $scope.numberToShow
        };

        $http.post(tfEncoder.encode("/configuration/users/search"), searchObject).
            then(function(response) {

                var data = response.data;

                if (data.success) {
                    $scope.countUsers = data.object.countUsers;
                    users = data.object.users;
                    lastSearchString = searchText;
                    lastNumber = $scope.numberToShow;
                    lastPage = $scope.page;
                    $scope.users = users;
                    selectUserWithId($scope.userId);
                } else {
                    $scope.errorMessage = "Failed to receive search results. Message was : " + data.message;
                }

                return users;
            });

    };

    function selectUserWithId(targetId) {
        if (!targetId) {
            $scope.currentUser = undefined;
            $scope.currentUrl = undefined;
            $rootScope.$broadcast('userNotAvailable');
            return;
        }

        var index = 0, targetIndex = -1;
        $scope.users.forEach(function (listUser) {
            if (listUser.id === targetId) {
                targetIndex = index;
            }
            index = index + 1;
        });

        if (targetIndex === -1) {
            $scope.currentUser = undefined;
            $rootScope.$broadcast('userNotAvailable');
            return;
        }

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
                    $scope.usersSuccessMessage = "Edit succeeded.";

                    $scope.users = data.object;

                    selectUserWithId($scope.currentUser.id);
                } else {

                    if (data.errorMap && data.errorMap.name) {
                        $scope.errorMessage = "Failure. " + data.errorMap.name;
                    } else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }
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

                $scope.usersSuccessMessage = "Successfully added permissions.";

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
                $scope.usersSuccessMessage = "Successfully edited permissions.";
            } else {
                $scope.usersSuccessMessage = "Permissions object was successfully deleted.";
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
                        $rootScope.$broadcast('refreshGroups');
                        $scope.usersSuccessMessage = "User was successfully deleted.";
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
                        $scope.usersSuccessMessage = "Permission was successfully deleted.";
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
        reloadList();
    });

    ////////////////////////////////////////////////////////////////////////////////
    //                            Groups
    ////////////////////////////////////////////////////////////////////////////////

    $scope.$on('groups', function(event, groups) {
        $scope.groups = groups;
    });

    $scope.addGroup = function(group) {
        if (!group || !group.id) {
            return;
        }

        $http.post(tfEncoder.encode('/groups/' + group.id + '/addUser/' + $scope.userId)).
            success(function(data) {
                if (data.success) {
                    reloadList();
                    $rootScope.$broadcast('refreshGroups');
                    $scope.usersSuccessMessage = "Added user to group " + group.name + ".";
                } else {
                    $scope.errorMessage = "Failure. " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to add user to group. HTTP status was " + status;
            });
    };

    $scope.removeGroup = function(group) {
        if (confirm("Are you sure you want to remove user from group " + group.name + "?")) {
            $http.post(tfEncoder.encode('/groups/' + group.id + '/removeUser/' + $scope.userId)).
                success(function(data) {
                    if (data.success) {
                        reloadList();
                        $rootScope.$broadcast('refreshGroups');
                        $scope.usersSuccessMessage = "Removed user from group " + group.name;
                    } else {
                        $scope.errorMessage = "Failure. " + data.message;
                    }

                    $scope.initialized = true;
                }).
                error(function(data, status) {
                    $scope.initialized = true;
                    $scope.errorMessage = "Failed to remove user from group. HTTP status was " + status;
                });
        }
    };

    $scope.createNewKey = function(user) {
        var modalInstance = $modal.open({
            templateUrl: 'newKeyModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/users/" + user.id + "/keys/new");
                },
                object: function() {
                    return { username: user.name };
                },
                buttonText: function() {
                    return "Create Key";
                }
            }
        });

        modalInstance.result.then(function (key) {

            if (!$scope.currentUser.apiKeys || !$scope.currentUser.apiKeys.length) {
                $scope.currentUser.apiKeys = [ key ];
            } else {
                $scope.currentUser.apiKeys.push(key);
            }

            $scope.userSuccessMessage = "Successfully created key.";

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openEditModal = function(user, key) {
        var modalInstance = $modal.open({
            templateUrl: 'editKeyModal.html',
            controller: 'GenericModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/users/" + user.id + "/keys/" + key.id + "/edit");
                },
                object: function() {
                    var keyCopy = angular.copy(key);
                    return keyCopy;
                },
                buttonText: function() {
                    return "Save Edits";
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/users/" + user.id + "/keys/" + key.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedKey) {

            if (editedKey) {
                threadFixModalService.deleteElement($scope.currentUser.apiKeys, key);
                threadFixModalService.addElement($scope.currentUser.apiKeys, editedKey);

                $scope.successMessage = "Successfully edited key " + editedKey.apiKey;
            } else {
                threadFixModalService.deleteElement($scope.currentUser.apiKeys, key);
                $scope.successMessage = "API key was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

});
