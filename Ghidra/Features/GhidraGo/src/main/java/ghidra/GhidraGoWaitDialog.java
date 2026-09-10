/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.label.GIconLabel;
import ghidra.util.Swing;

public class GhidraGoWaitDialog extends DialogComponentProvider {
	private static final String BASE_MESSAGE = """
			<html><center>
			If Ghidra has started, please confirm the GhidraGoPlugin has been added in<br>
			<br>
			<b>File</b> &rarr; <b>Configure</b> in the Ghidra project manager.<br>
			<br>
			If GhidraGoPlugin has been configured, make sure Ghidra has an active project.
			<br>
			<br>
			%s<br>
			<br>
			Would you like to keep waiting?<br>
			</center>""";

	public enum WAIT_DIALOG_RESULT { WAIT, DO_NOT_WAIT }


	private GDHtmlLabel msgText;
	private volatile long elapsedMS;
	private volatile WAIT_DIALOG_RESULT result;
	private String lastUpdateMessage;

	public GhidraGoWaitDialog() {
		super("GhidraGo Taking Longer Than Expected", true);

		addWorkPanel(buildMainPanel());

		JButton waitButton = new JButton("Wait");
		waitButton.getAccessibleContext().setAccessibleName("Wait");
		waitButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				result = WAIT_DIALOG_RESULT.WAIT;
				close();
			}
		});
		addButton(waitButton);

		JButton noWaitButton = new JButton("No");
		noWaitButton.getAccessibleContext().setAccessibleName("No Wait");
		noWaitButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				result = WAIT_DIALOG_RESULT.DO_NOT_WAIT;
				close();
			}
		});
		addButton(noWaitButton);
	}

	public WAIT_DIALOG_RESULT getResult() {
		return result;
	}

	@Override
	protected void cancelCallback() {
		result = WAIT_DIALOG_RESULT.DO_NOT_WAIT;
		super.cancelCallback();
	}

	public void updateMessage(String additionalMsg, long newElapsedMS) {
		if (additionalMsg != lastUpdateMessage || newElapsedMS < elapsedMS ||
			elapsedMS + 500 < newElapsedMS) {
			lastUpdateMessage = additionalMsg;
			elapsedMS = newElapsedMS;
			String elapsedMsg =
				"%s (%d seconds elapsed)".formatted(additionalMsg, newElapsedMS / 1000);
			String newMsg = BASE_MESSAGE.formatted(elapsedMsg);
			Swing.runLater(() -> msgText.setText(newMsg));
		}
	}

	private JPanel buildMainPanel() {
		JPanel innerPanel = new JPanel();
		innerPanel.setLayout(new BorderLayout());
		innerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		innerPanel.add(
			new GIconLabel(OptionDialog.getIconForMessageType(OptionDialog.WARNING_MESSAGE)),
			BorderLayout.WEST);

		JPanel msgPanel = new JPanel(new BorderLayout());
		msgPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
		msgPanel.getAccessibleContext().setAccessibleName("Message");

		msgText = new GDHtmlLabel(BASE_MESSAGE.formatted("<br>"));
		msgText.getAccessibleContext().setAccessibleName("Message Text");

		msgPanel.add(msgText, BorderLayout.CENTER);

		innerPanel.add(msgPanel, BorderLayout.CENTER);
		innerPanel.getAccessibleContext().setAccessibleName("Ghidra Go Wait");
		return innerPanel;
	}
}
