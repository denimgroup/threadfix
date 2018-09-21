<%@ include file="/common/taglibs.jsp"%>

<html>
    <head>
        <title>About ThreadFix</title>
    </head>
    <body>
        <h2>About ThreadFix</h2>
        <div>
            <p>
                ThreadFix is a software vulnerability aggregation and management system that helps organizations aggregate vulnerability data, generate virtual patches, and interact with software defect tracking systems.
            </p>
            <p>
                Important Links:<br />
                <ul>
                    <li>
                        <a href="http://www.threadfix.org/" target="_blank">Main ThreadFix Site</a>
                    </li>
                    <li>
                        <a href="https://github.com/denimgroup/threadfix" target="_blank">ThreadFix GitHub Site</a>
                    </li>
                    <li>
                        <a href="https://groups.google.com/forum/?fromgroups#!forum/threadfix" target="_blank">ThreadFix Google Group (Community Support)</a>
                    </li>
                </ul>
            </p>
        </div>
        <h2>About This ThreadFix Build</h2>
        <div>
            <b>Last commit:</b> <a href="https://github.com/denimgroup/threadfix/commit/${requestScope.gitCommit}" class="commit-id" target="_blank">${requestScope.gitCommit}</a>
        </div>
        <div>
            <b>Build date:</b> <fmt:formatDate value="${requestScope.buildDate}" pattern="MMM dd, yyyy hh:mm a zzz"/>
        </div>
    </body>
</html>
