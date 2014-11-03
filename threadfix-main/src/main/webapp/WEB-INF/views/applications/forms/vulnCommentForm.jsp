<script type="text/ng-template" id="vulnCommentForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">Add Comment</h4>
    </div>
    <div ng-form="form" class="modal-body input-group">
        <c:if test="${ not empty commentError }">
            <div id="commentError${ vulnerability.id }" class="alert alert-error hide-after-submit">
                <c:out value="${ commentError }"/>
            </div>
        </c:if>
        <div style="display:none" id="lengthError${ vulnerability.id }" class="alert alert-error hide-after-submit">
            Maximum length is 200 characters.
        </div>
        <table class="modal-form-table">
            <tr class="left-align">
                <td>Tag</td>
                <td class="left-align">
                    <multi-select id="tagSelect"
                            input-model="config.tags"
                            output-model="object.tags"
                            button-label="name"
                            item-label="name"
                            tick-property="selected"
                            >
                    </multi-select>
                </td>
            </tr>
            <tr class="left-align">
                <td>Comment</td>
                <td>
                    <textarea style="margin:10px;width: 397px; height: 215px;"
                              focus-on="focusInput"
                              ng-model="object.comment" class="textbox clear-after-submit"
                              id="commentInputBox"
                              ng-maxlength="200"
                              name="comments"></textarea>
                </td>
            </tr>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>