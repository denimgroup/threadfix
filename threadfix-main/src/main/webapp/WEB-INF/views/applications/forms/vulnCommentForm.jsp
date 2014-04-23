<script type="text/ng-template" id="vulnCommentForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Add Comment</h4>
    </div>
    <div ng-form="form" class="modal-body">
        <c:if test="${ not empty commentError }">
            <div id="commentError${ vulnerability.id }" class="alert alert-error hide-after-submit">
                <c:out value="${ commentError }"/>
            </div>
        </c:if>
        <div style="display:none" id="lengthError${ vulnerability.id }" class="alert alert-error hide-after-submit">
            Maximum length is 200 characters.
        </div>
        <textarea style="margin:10px;width: 497px; height: 215px;"
                  focus-on="focusInput"
            ng-model="object.comments" class="textbox clear-after-submit"
            id="commentInputBox"
            ng-maxlength="200"
            name="comments"></textarea>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>