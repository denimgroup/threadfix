////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.webapp.viewmodels;

import java.util.ArrayList;
import java.util.List;

public class PathTree {
	
	private Node root;
	private int depth;
	private List<List<String>> printout;

	public PathTree(Node root) {
		this.root = root;
		depth = 0;
		printout = new ArrayList<>();
	}

	public Node getRoot() {
		return root;
	}

	public void setRoot(Node root) {
		this.root = root;
	}

	public int getDepth() {
		return depth;
	}

	public void setLevel(int depth) {
		this.depth = depth;
	}

	public List<List<String>> getPrintout() {
		for (List<String> pathPrint : printout) {
			for (int i = 0; i < depth - pathPrint.size(); i++) {
				pathPrint.add(null);
			}
		}
		return printout;
	}

	public void setPrintout(List<List<String>> printout) {
		this.printout = printout;
	}

	public void addPath(String path) {
		String editedPath = path;
		
		editedPath = editedPath.trim();
		editedPath = editedPath.replaceAll("^[\\\\|/]", "");
		editedPath = editedPath.replaceAll("[\\\\|/]$", "");
		List<String> pathList = new ArrayList<>();
		String[] pathArray = editedPath.split("[\\\\|/]");
		Node node = root;
		for (int i = 0; i < pathArray.length; i++) {
			boolean found = false;
			List<Node> childNode = node.getChildNode();
			for (Node child : childNode) {
				if (pathArray[i].equals(child.getData())) {
					found = true;
					node = child;
					pathList.add(null);
					break;
				}
			}
			if (!found) {
				Node newChild = new Node(pathArray[i]);
				node.appendChild(newChild);
				pathList.add(pathArray[i]);
				if (depth < i + 1) {
					depth = i + 1;
				}
				node = newChild;
			}
		}
		printout.add(pathList);
	}
}
