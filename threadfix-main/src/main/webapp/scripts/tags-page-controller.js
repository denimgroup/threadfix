var module = angular.module('threadfix');

module.controller('TagsPageController', function($scope, $http, $modal, $log, tfEncoder){

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.tagChecked = {allChecked: false};

    $scope.refresh = function() {
        $http.get(tfEncoder.encode('/configuration/tags/map')).
            success(function (data) {
                if (data.success) {
                    $scope.tags = data.object.tags;
                    $scope.tags.sort(nameCompare);

                    $scope.vulnTags = data.object.vulnTags;
                    $scope.vulnTags.sort(nameCompare);

                    $scope.commentTags = data.object.commentTags;
                    $scope.commentTags.sort(nameCompare);

                    $scope.tagTypes = data.object.tagTypes;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
                $scope.initialized = true;
            }).
            error(function (data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    };

    $scope.$on('rootScopeInitialized', $scope.refresh);

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'createTagModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/tags/new");
                },
                object: function () {
                    return {type: $scope.tagTypes[0]};
                },
                config: function() {
                    return {tagTypes: $scope.tagTypes};
                },
                buttonText: function() {
                    return "Create Tag";
                }
            }
        });

        $scope.currentModal = modalInstance;
        modalInstance.result.then(function (tag) {

            $scope.refresh();

            $scope.successMessage = "Successfully created tag " + tag.name;
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

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
                $scope.successMessage = "Successfully edited tag " + tag.name;
                $scope.refresh();
            } else {
                $scope.errorMessage = "Failed to delete tag " + tag.name +
                    ". Make sure there are no applications or tags associated with the tag and try again.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.goToTag = function(tag) {
        window.location.href = tfEncoder.encode("/configuration/tags/" + tag.id +"/view");
    };

    $scope.goToBatchTagging = function() {
        var tagIds = null;
        $scope.tags.forEach(function(tag){
            if (tag.checked) {
                tagIds = tagIds ? (tagIds + "-" + tag.id) : tag.id;
            }
        });
        window.location.href = tfEncoder.encode('/configuration/tags/batchTagging/' + tagIds);
    };

    $scope.applyAllTagsChecked = function(allChecked) {
        $scope.allChecked = allChecked;
        if ($scope.tags) {
            $scope.tags.forEach(function(tag){
                tag.checked = allChecked;
            });
        }
    };

    $scope.applyTagChecked = function(tag) {
        if (!tag.checked) {
            $scope.tagChecked.allChecked = false;
        }
        else {
            var checked = true;
            $scope.tags.forEach(function(appTag){
                if (!appTag.checked)
                    checked = false;
            });
            $scope.tagChecked.allChecked = checked;
        }
    }

});