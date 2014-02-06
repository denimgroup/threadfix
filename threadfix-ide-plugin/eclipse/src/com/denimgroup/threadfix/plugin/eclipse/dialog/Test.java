package com.denimgroup.threadfix.plugin.eclipse.dialog;

/*
 * Tree snippet: implement standard tree check box behavior (SWT.CHECK)
 * 
 * For a list of all SWT example snippets see
 * http://www.eclipse.org/swt/snippets/
 * 
 * @since 3.3
 */
import org.eclipse.swt.SWT;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Tree;
import org.eclipse.swt.widgets.TreeItem;

public class Test {

	static void checkPath(TreeItem item, boolean checked, boolean grayed) {
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
					break;
				}
				index++;
			}
		}
		item.setChecked(checked);
		item.setGrayed(grayed);
		checkPath(item.getParentItem(), checked, grayed);
	}

	static void checkItems(TreeItem item, boolean checked) {
		item.setGrayed(false);
		item.setChecked(checked);
		TreeItem[] items = item.getItems();
		for (TreeItem item2 : items) {
			checkItems(item2, checked);
		}
	}

	public static void main(String[] args) {
		Display display = new Display();
		Shell shell = new Shell(display);
		Tree tree = new Tree(shell, SWT.BORDER | SWT.CHECK);
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
		for (int i = 0; i < 4; i++) {
			TreeItem itemI = new TreeItem(tree, SWT.NONE);
			itemI.setText("Item " + i);
			for (int j = 0; j < 4; j++) {
				TreeItem itemJ = new TreeItem(itemI, SWT.NONE);
				itemJ.setText("Item " + i + " " + j);
				for (int k = 0; k < 4; k++) {
					TreeItem itemK = new TreeItem(itemJ, SWT.NONE);
					itemK.setText("Item " + i + " " + j + " " + k);
				}
			}
		}
		Rectangle clientArea = shell.getClientArea();
		tree.setBounds(clientArea.x, clientArea.y, 200, 200);
		shell.pack();
		shell.open();
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
		display.dispose();
	}

}