var module = angular.module('threadfix')

module.controller('RolesPageController', function($scope, $http, $modal, $log, tfEncoder){

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/roles/list')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.roles = data.object;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve role list. HTTP status was " + status;
            });
    });

    $scope.openNewRoleModal = function() {

        var modalInstance = $modal.open({
            templateUrl: 'newRoleModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/roles/new");
                },
                object: function () {
                    return {
                         "canGenerateReports": "false",
                         "canGenerateWafRules": "false",
                         "canManageApiKeys": "false",
                         "canManageApplications": "false",
                         "canManageDefectTrackers": "false",
                         "canManageRemoteProviders": "false",
                         "canManageRoles": "false",
                         "canManageTeams": "false",
                         "canViewJobStatuses": "false",
                         "canViewErrorLogs": "false",
                         "canUploadScans": "false",
                         "canSubmitDefects": "false",
                         "canModifyVulnerabilities": "false",
                         "canManageWafs": "false",
                         "canManageUsers": "false"
                    };
                },
                config: function() {
                    return {
                        //wafTypeList: $scope.wafTypes
                    }
                },
                buttonText: function() {
                    return "Create Role";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (role) {
            if (!$scope.roles) {
                $scope.roles = [ role ];
            } else {
                $scope.roles.push(role);

                $scope.roles.sort(nameCompare);
            }

            $scope.successMessage = "Successfully created role " + role.name;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openEditModal = function(role) {
        var modalInstance = $modal.open({
            templateUrl: 'editRoleModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/roles/" + role.id + "/edit");
                },
                object: function() {
                    return role;
                },
                buttonText: function() {
                    return "Save Edits";
                },
                config: function() {
                    return {
                        // wafTypeList: $scope.wafTypes
                    }
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/roles/" + role.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedRole) {
            var index = $scope.roles.indexOf(role);

            if (index > -1) {
                $scope.roles.splice(index, 1);
            }

            if (editedRole) {
                $scope.roles.push(editedRole);

                $scope.roles.sort(nameCompare);
                $scope.successMessage = "Successfully edited role " + editedRole.name;
            } else {
                $scope.successMessage = "Role deletion was successful for Role " + editedRole.name;
            }

            if ($scope.roles.length === 0){
                $scope.roles = undefined;
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.goToRole = function(role) {
        window.location.href = tfEncoder.encode("/configuration/roles/" + role.id);
    }

});