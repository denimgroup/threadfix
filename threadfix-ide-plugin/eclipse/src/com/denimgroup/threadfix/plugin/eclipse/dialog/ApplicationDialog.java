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
package com.denimgroup.threadfix.plugin.eclipse.dialog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.jface.dialogs.TitleAreaDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Tree;
import org.eclipse.swt.widgets.TreeItem;

public class ApplicationDialog extends TitleAreaDialog {
	
	private List<TreeItem> treeNodes = new ArrayList<TreeItem>();

	private Set<String> appIds = null;

	private final Map<String, String> appIdMap;
	private final Map<String, List<List<String>>> appTeamMap;
	private final Set<String> alreadyChecked;

	public ApplicationDialog(Shell parentShell, Map<String, String> appIdMap,
			Set<String> alreadyChecked) {
		super(parentShell);
		this.appIdMap = appIdMap;
		this.alreadyChecked = alreadyChecked;
		appTeamMap = organizeAppsByTeam();
	}

	@Override
	public void create() {
		super.create();
		setTitle("Pick Applications");
	}

	@Override
	protected Control createDialogArea(Composite parent) {
		Composite area = (Composite) super.createDialogArea(parent);
		Composite container = new Composite(area, SWT.BORDER);
		container.setLayoutData(new GridData(SWT.FILL, SWT.FILL, false, true, 1, 1));
		container.setBounds(0, 4, 255, 254);
		container.setLayout(new FillLayout());

		createApplicationSelectionTree(container);
		return area;
	}
	
	private void  createApplicationSelectionTree(Composite container){
		Tree tree = new Tree (container, SWT.BORDER | SWT.CHECK);
	    tree.addListener(SWT.Selection, new Listener() {
	        @Override
			public void handleEvent(Event event) {
	            if (event.detail == SWT.CHECK) {
	                TreeItem item = (TreeItem) event.item;
	                boolean checked = item.getChecked();
	                checkItems(item, checked);
	                checkPath(item.getParentItem(), checked, false);
	            }
	        }
	    });
		for(String Team : appTeamMap.keySet()){
			TreeItem teamItem = new TreeItem (tree, 0);
			teamItem.setText (Team);
			for(List<String> app : appTeamMap.get(Team)){
				TreeItem appItem = new TreeItem(teamItem,0);
				appItem.setText(app.get(0));
				appItem.setData(app.get(0),app.get(1));
				if (alreadyChecked.contains(app.get(1)) && !appItem.getChecked()) {
					appItem.setChecked(true);
					treeNodes.add(appItem);
				}
			}
		}
	}
	
	private Map<String,List<List<String>>> organizeAppsByTeam(){
		Map<String,List<List<String>>> teamMap = new HashMap<>();
		for(String teamApp : appIdMap.keySet()){
			String[] comps = teamApp.split("/");
			if(comps.length==2){
				List<List<String>> temp = teamMap.get(comps[0]);
				List<String> sub = new ArrayList<>();
				sub.add(comps[1]);
				sub.add(appIdMap.get(teamApp));
				if(temp!=null){
					temp.add(sub);
				
				}else{
					temp = new ArrayList<>();
					temp.add(sub);
				}
				teamMap.put(comps[0], temp);
			}
		}
		return teamMap;
	}

	@Override
	protected boolean isResizable() {
		return true;
	}

	// We need to save the values of the Text fields into Strings because the UI
	// gets disposed and the Text fields are not accessible any more.
	private void saveInput() {
		appIds = getAppIdsFromTreeNodes();
	}
	
	private Set<String> getAppIdsFromTreeNodes(){
		Set<String> returnSet = new HashSet<String>();
		for(TreeItem node : treeNodes){
			if (node.getChecked()){
				returnSet.add((String) node.getData(node.getText()));
			}
		}
		
		return returnSet;
	}

	@Override
	protected void okPressed() {
		saveInput();
		super.okPressed();
	}
	
	public Set<String> getAppIds() {
		return appIds;
	}
	
	private void checkPath(TreeItem item, boolean checked, boolean grayed) {
	    if (item == null) {
			return;
		}
	    if (grayed) {
	        checked = true;
	    } else {
	        int index = 0;
	        TreeItem[] items = item.getItems();
	        while (index < items.length) {
	            TreeItem child = items[index];
	            if (child.getGrayed() || checked != child.getChecked()) {
	                checked = grayed = true;
	                treeNodes.add(child);
	                break;
	            }
	            index++;
	        }
	    }
	    item.setChecked(checked);
	    item.setGrayed(grayed);
	    checkPath(item.getParentItem(), checked, grayed);
	}

	private void checkItems(TreeItem item, boolean checked) {
	    item.setGrayed(false);
	    item.setChecked(checked);
	    treeNodes.add(item);
	    TreeItem[] items = item.getItems();
	    for (TreeItem item2 : items) {
	        checkItems(item2, checked);
	    }
	}
}
