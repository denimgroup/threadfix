var module = angular.module('threadfix');

module.controller('RolesPageController', function($scope, $http, $modal, $log, tfEncoder){

    var nameCompare = function(a,b) {
        return a.displayName.localeCompare(b.displayName);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/roles/list')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.roles = data.object;
                    $scope.roles.sort(nameCompare);

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
            controller: 'RoleEditModalController',
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
                         "canManageGrcTools": "false",
                         "canManageDefectTrackers": "false",
                         "canManageRemoteProviders": "false",
                         "canManageScanAgents": "false",
                         "canManageSystemSettings": "false",
                         "canManageRoles": "false",
                         "canManageTags": "false",
                         "canManageTeams": "false",
//                         "canViewJobStatuses": "false",
                         "canViewErrorLogs": "false",
                         "canUploadScans": "false",
                         "canSubmitDefects": "false",
                         "canModifyVulnerabilities": "false",
                         "canManageVulnFilters": "false",
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

            $scope.successMessage = "Successfully created role " + role.displayName;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    var addKeys = function(role) {

        if (!role.stringed) {
            role.canGenerateReports = role.canGenerateReports === true ? "true" : "false";
            role.canGenerateWafRules = role.canGenerateWafRules === true ? "true" : "false";
            role.canManageApiKeys = role.canManageApiKeys === true ? "true" : "false";
            role.canManageApplications = role.canManageApplications === true ? "true" : "false";
            role.canManageGrcTools = role.canManageGrcTools === true ? "true" : "false";
            role.canManageDefectTrackers = role.canManageDefectTrackers === true ? "true" : "false";
            role.canManageRemoteProviders = role.canManageRemoteProviders === true ? "true" : "false";
            role.canManageScanAgents = role.canManageScanAgents === true ? "true" : "false";
            role.canManageSystemSettings = role.canManageSystemSettings === true ? "true" : "false";
            role.canManageRoles = role.canManageRoles === true ? "true" : "false";
            role.canManageTags = (role.canManageTags === true)? "true" : "false";
            role.canManageTeams = role.canManageTeams === true ? "true" : "false";
            role.canViewErrorLogs = role.canViewErrorLogs === true ? "true" : "false";
            role.canUploadScans = role.canUploadScans === true ? "true" : "false";
            role.canSubmitDefects = role.canSubmitDefects === true ? "true" : "false";
            role.canModifyVulnerabilities = role.canModifyVulnerabilities === true ? "true" : "false";
            role.canManageVulnFilters = role.canManageVulnFilters === true ? "true" : "false";
            role.canManageWafs = role.canManageWafs === true ? "true" : "false";
            role.canManageUsers = role.canManageUsers === true ? "true" : "false";

            role.stringed = true;
        }
    };

    $scope.openEditModal = function(role) {
        var modalInstance = $modal.open({
            templateUrl: 'editRoleModal.html',
            controller: 'RoleEditModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/roles/" + role.id + "/edit");
                },
                object: function() {
                    addKeys(role);
                    var roleCopy = angular.copy(role);
                    return roleCopy;
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
                $scope.successMessage = "Successfully edited role " + editedRole.displayName;
            } else {
                $scope.successMessage = "Role deletion was successful for Role " + role.displayName;
            }

            if ($scope.roles.length === 0){
                $scope.roles = undefined;
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.goToRole = function(role) {
        window.location.href = tfEncoder.encode("/configuration/roles/" + role.id);
    }

});