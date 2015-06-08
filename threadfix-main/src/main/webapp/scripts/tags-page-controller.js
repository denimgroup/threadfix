var module = angular.module('threadfix')

module.controller('TagsPageController', function($scope, $http, $modal, $log, tfEncoder){

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/tags/map')).
            success(function(data) {
                if (data.success) {
                    if (data.object.tags.length > 0) {
                        $scope.tags = data.object.tags;
                        $scope.tags.sort(nameCompare);
                    }
                    if (data.object.commentTags.length > 0) {
                        $scope.commentTags = data.object.commentTags;
                        $scope.commentTags.sort(nameCompare);
                    }
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {

        var modalInstance = $modal.open({
            templateUrl: 'createTagModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/tags/new");
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {};
                },
                buttonText: function() {
                    return "Create Tag";
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (tag) {
            if (tag.tagForComment) {
                if (!$scope.commentTags) {
                    $scope.commentTags = [ tag ];
                } else {
                    $scope.commentTags.push(tag);
                    $scope.commentTags.sort(nameCompare);
                }
            } else {
                if (!$scope.tags) {
                    $scope.tags = [ tag ];
                } else {
                    $scope.tags.push(tag);
                    $scope.tags.sort(nameCompare);
                }
            }

            $scope.successMessage = "Successfully created tag " + tag.name;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openEditModal = function(tag) {
        if (tag.enterpriseTag)
            return;
        var modalInstance = $modal.open({
            templateUrl: 'editTagModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/tags/" + tag.id + "/edit");
                },
                object: function() {
                    return angular.copy(tag);
                },
                buttonText: function() {
                    return "Save Edits";
                },
                config: function() {
                    return {}
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/tags/" + tag.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (tagsMap) {

            if (tagsMap) {
                $scope.tags = tagsMap.tags;
                $scope.commentTags = tagsMap.commentTags;
                $scope.tags.sort(nameCompare);
                $scope.commentTags.sort(nameCompare);
                $scope.errorMessage = "";
                $scope.successMessage = "Successfully edited tag " + tag.name;
            } else {
                if (tag.deletable) {
                    if (!tag.tagForComment) {
                        var index = $scope.tags.indexOf(tag);
                        if (index > -1) {
                            $scope.tags.splice(index, 1);
                        }
                        if ($scope.tags.length === 0) {
                            $scope.tags = undefined;
                        }
                    } else {
                        var index = $scope.commentTags.indexOf(tag);
                        if (index > -1) {
                            $scope.commentTags.splice(index, 1);
                        }
                        if ($scope.commentTags.length === 0) {
                            $scope.commentTags = undefined;
                        }
                    }
                    $scope.successMessage = "The deletion was successful for Tag " + tag.name;
                    $scope.errorMessage = "";
                } else {
                    $scope.successMessage = "";
                    $scope.errorMessage = "Failed to delete a Tag with applications or vulnerability comment mappings.";
                }
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.goToTag = function(tag) {
        window.location.href = tfEncoder.encode("/configuration/tags/" + tag.id +"/view");
    }

});