var myAppModule = angular.module('threadfix');

myAppModule.controller('UserAuditPageController', function ($scope, $modal, $http, $log, $rootScope, tfEncoder, $filter) {

    ////////////////////////////////////////////////////////////////////////////////
    //             Basic Page Functionality + $on(rootScopeInitialized)
    ////////////////////////////////////////////////////////////////////////////////

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    var browerErrMsg = "Sorry, your browser does not support this feature. Please upgrade IE version or change to Chrome which is recommended.";

    $scope.activateTab = function(tab) {
        $scope.active = {}; //reset
        $scope.active[tab] = true;
        $rootScope.title = tab[0].toUpperCase() + tab.substr(1);
    };

    $scope.numberToShow = 10;

    $scope.updatePage = function(page) {
        $scope.page = page;
        reloadList();
    };

    $scope.$on('rootScopeInitialized', function() {
        reloadList();
    });

    $scope.$on('refreshUsers', function() {
        reloadList();
    });

    $scope.$on('refreshGroups', function() {
        reloadList();
    });

    $scope.$on('updateAuditRoles', function() {
        reloadList();
    });

    $scope.$on('reloadRoles', function() {
        reloadList();
    });

    var reloadList = function() {
        $scope.initialized = false;

        $http.get(tfEncoder.encode('/configuration/users/map/page/' + $scope.page + '/' + $scope.numberToShow)).
            success(function(data) {

                if (data.success) {
                    $scope.countUsers = data.object.countUsers;
                    if (data.object.users.length > 0) {
                        $scope.users = data.object.users;
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

    $scope.getAllUsers = function(callback) {

        var users = [];

        $http.get(tfEncoder.encode('/configuration/users/all')).
            success(function(data) {

                if (data.success) {
                    callback(data.object);
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve user list. HTTP status was " + status;
            });

        return users;
    };

    $scope.openGroups = function(user) {

        $modal.open({
            templateUrl: 'groupsListModal.html',
            controller: 'ModalController',
            resolve: {
                data: function() {
                    return {
                        heading: 'User Groups',
                        list: user.groups
                    }
                }
            }
        });
    };

    $scope.openRoles = function(user) {

        var teamMaps = user.accessControlTeamMaps;
        var appMaps = getAppRoles(teamMaps);

        $modal.open({
            templateUrl: 'rolesListModal.html',
            controller: 'ModalController',
            resolve: {
                data: function() {
                    return {
                        heading: 'User Roles',
                        teamMaps: teamMaps,
                        appMaps: appMaps,
                        userGlobalRole: user.globalRole != null ? user.globalRole.displayName : '--'
                    }
                }
            }
        });
    };

    var getAppRoles = function(teamMaps) {

        var appMaps = [];

        for (var i = 0; i < teamMaps.length; i++) {
            var appRoles = teamMaps[i].appRoles;

            for (var j = 0; j < appRoles.length; j++) {
                var appRole = appRoles[j];
                appMaps.push(appRole);
            }
        }

        return appMaps;
    };

    var checkOldIE = function() {
        // IE <10, unsupported
        return (typeof navigator !== "undefined" &&
        /MSIE [1-9]\./.test(navigator.userAgent));
    };

    $scope.exportPDF = function() {

        if (checkOldIE()) {
            alert(browerErrMsg);
            return;
        }

        $scope.getAllUsers(function(users) {

            var data = [];
            var doc = new jsPDF('l', 'pt');
            var now = new Date();

            doc.text("Users Audit Report (" + $filter('date')(now, 'short') + ")" , 10, doc.autoTableEndPosY() + 30);

            for (var i = 0; i < users.length; i++) {

                var user = users[i];
                var groups = user.groups.map(function(group) {
                    return group.name;
                }).join(", ");

                var roles = "Global Role: " + (user.globalRole != null ? user.globalRole.displayName : "--");

                var teamRoles = [];

                for (var j = 0; j < user.accessControlTeamMaps.length; j++) {
                    var teamMap = user.accessControlTeamMaps[j];
                    if ( teamMap.roleName !== '-') {
                        teamRoles.push(teamMap.roleName + " (" + teamMap.teamName + ")");
                    }
                }

                if ( teamRoles.length > 0 ) {
                    roles += "\nTeam Roles: " + teamRoles.join(", ");
                }

                var appMaps = getAppRoles(user.accessControlTeamMaps);
                var appRoles = [];

                for (var k = 0; k < appMaps.length; k++) {
                    var appMap = appMaps[k];
                    if ( appMap.roleName !== '-') {
                        appRoles.push(appMap.roleName + " (" + appMap.teamName + ":" + appMap.appName + ")");
                    }
                }

                if ( appRoles.length > 0 ) {
                    roles += "\nApp Roles: " + appRoles.join(", ");
                }

                data.push({
                    "name" : user.displayName ? user.displayName : "-",
                    "username" : user.name,
                    "lastLogIn" : $filter('date')(user.lastLoginDate, 'medium'),
                    "groups" : groups,
                    "roles" : roles
                });
            }

            var columns = [
                {title: "Name", key: "name"},
                {title: "Username", key: "username"},
                {title: "Last Log In", key: "lastLogIn"},
                {title: "Groups", key: "groups"},
                {title: "Roles", key: "roles"}
            ];

            doc.autoTable(columns, data, {
                margins: {
                    horizontal: 10,
                    top: 40,
                    bottom: 40
                },
                avoidPageSplit: true,
                startY: 50,
                overflow: 'linebreak',
                overflowColumns: ['roles', 'groups'],
                columnWidths: [
                    {width: 150, key: "groups"},
                    {width: 200, key: "roles"}
                ]
            });

            doc.save("user-audit-report-" + $filter('date')(now, 'yyyyMMddHHmmss') + ".pdf");
        });
    };

});
