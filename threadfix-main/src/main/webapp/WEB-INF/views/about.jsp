<%@ include file="/common/taglibs.jsp"%>

<html>
    <head>
        <title>About</title>
    </head>
    <body>
        <h2>About</h2>
        <div>
            <b>Last commit:</b> <a href="https://github.com/denimgroup/threadfix/commit/${requestScope.gitCommit}" class="commit-id">${requestScope.gitCommit}</a>
        </div>
        <div>
            <b>Build date:</b> <fmt:formatDate value="${requestScope.buildDate}" pattern="MMM dd, yyyy hh:mm a zzz"/>
        </div>
    </body>
</html>
