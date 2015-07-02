var module = angular.module('threadfix')

module.controller('TagsPageController', function($scope, $http, $modal, $log, tfEncoder){

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.tagChecked = {allChecked: false};

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/tags/map')).
            success(function(data) {
                if (data.success) {
                    if (data.object.tags.length > 0) {
                        $scope.tags = data.object.tags;
                        $scope.tags.sort(nameCompare);
                    }

                    if (data.object.vulnTags.length > 0) {
                        $scope.vulnTags = data.object.vulnTags;
                        $scope.vulnTags.sort(nameCompare);
                    }

                    if (data.object.commentTags.length > 0) {
                        $scope.commentTags = data.object.commentTags;
                        $scope.commentTags.sort(nameCompare);
                    }
                    $scope.tagTypes = data.object.tagTypes;
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

            var collection;
            if (tag.type == "APPLICATION")
                collection = $scope.tags;
            else if (tag.type == "VULNERABILITY")
                collection = $scope.vulnTags;
            else
                collection = $scope.commentTags;

            if (!collection) {
                collection = [ tag ];
            } else {
                collection.push(tag);
                collection.sort(nameCompare);
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
                $scope.vulnTags = tagsMap.vulnTags;
                $scope.commentTags = tagsMap.commentTags;
                $scope.tags.sort(nameCompare);
                $scope.vulnTags.sort(nameCompare);
                $scope.commentTags.sort(nameCompare);
                $scope.errorMessage = "";
                $scope.successMessage = "Successfully edited tag " + tag.name;
            } else {
                if (tag.deletable) {
                    var collection;
                    if (tag.type == "APPLICATION")
                        collection = $scope.tags;
                    else if (tag.type == "VULNERABILITY")
                        collection = $scope.vulnTags;
                    else
                        collection = $scope.commentTags;

                    var index = collection.indexOf(tag);
                    if (index > -1) {
                        collection.splice(index, 1);
                    }
                    if (collection.length === 0) {
                        collection = undefined;
                    }
                    $scope.successMessage = "The deletion was successful for Tag " + tag.name;
                    $scope.errorMessage = "";
                } else {
                    $scope.successMessage = "";
                    $scope.errorMessage = "Failed to delete a Tag with associated mappings.";
                }
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.goToTag = function(tag) {
        window.location.href = tfEncoder.encode("/configuration/tags/" + tag.id +"/view");
    }

    $scope.goToBatchTagging = function() {
        var tagIds = null;
        $scope.tags.forEach(function(tag){
            if (tag.checked) {
                tagIds = tagIds ? (tagIds + "-" + tag.id) : tag.id;
            }
        })
        window.location.href = tfEncoder.encode('/configuration/tags/batchTagging/' + tagIds);
    }

    $scope.applyAllTagsChecked = function(allChecked) {
        $scope.allChecked = allChecked;
        if ($scope.tags) {
            $scope.tags.forEach(function(tag){
                tag.checked = allChecked;
            });
        }
    }

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