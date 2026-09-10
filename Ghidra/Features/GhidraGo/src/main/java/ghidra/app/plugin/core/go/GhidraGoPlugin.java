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
package ghidra.app.plugin.core.go;

import java.net.URL;
import java.time.Duration;

import ghidra.GhidraGo;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.Application;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.*;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.Msg;
import ghidra.util.Swing;

//@formatter:off
@PluginInfo(
	category = PluginCategoryNames.COMMON,
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	shortDescription = "Listens for ghidraGo URLs",
	description =
			"Accepts ghidraGo URLs sent via named pipe IPC to activate the specified content," +
			"sent via the ghidraGo launch script",
	eventsConsumed = { ProjectPluginEvent.class })
//@formatter:on
public class GhidraGoPlugin extends Plugin implements ApplicationLevelOnlyPlugin {
	private NamedPipe pipe;
	private NamedPipeServer pipeServer;

	public GhidraGoPlugin(PluginTool tool) {
		super(tool);
		pipe = GhidraGo.getGhidraGoNamedPipe(Application.getApplicationLayout());
	}

	@Override
	protected void dispose() {
		releasePipe();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProjectPluginEvent ppe) {
			Project proj = ppe.getProject();
			if (proj == null) {
				releasePipe();
			}
			else {
				startListening();
			}
		}
	}

	public void releasePipe() {
		if (pipeServer != null) {
			pipeServer.close();
			pipeServer = null;
		}
	}

	public void startListening() {
		if (pipeServer != null) {
			return; // skip, already listening
		}
		Msg.info(this, "Starting GhidraGo Listener");
		pipeServer = pipe.createServer(this::handleMessageFromNamedPipe);
		pipeServer.start(Duration.ZERO);
	}

	private void handleMessageFromNamedPipe(String msg) {
		try {
			URL url = convertStringToURL(msg);

			URL projectUrl = GhidraURL.getProjectURL(url);

			// Check for case where remote server access has already been blocked to 
			// launching tool and then failing to access program. 
			if (!GhidraURL.isLocalURL(url) && !ClientUtil.getAllowListProvider().isAllowed(url)) {
				Msg.showError(this, tool.getActiveWindow(), "URL Access Not Allowed",
					"Access denied by Server Allow List:\n" + projectUrl);
				return;
			}

			Swing.runLater(() -> {
				FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
				frontEndTool.toFront();
				frontEndTool.accept(url);
			});
		}
		catch (IllegalArgumentException e) {
			Msg.error(this, "Bad GhidraGo message [%s]".formatted(msg), e);
		}
	}

	private URL convertStringToURL(String s) throws IllegalArgumentException {
		try {
			if (s.startsWith(GhidraURL.PROTOCOL + ":?")) {
				String projectFilePath = s.substring(s.indexOf("?") + 1);
				if (!projectFilePath.startsWith("/")) {
					projectFilePath = "/" + projectFilePath;
				}
				return GhidraURL.makeURL(AppInfo.getActiveProject().getProjectLocator(),
					projectFilePath, null);
			}
			return GhidraURL.toURL(s);

		}
		catch (IllegalArgumentException e) {
			if (s.startsWith(GhidraURL.PROTOCOL + "://") || AppInfo.getActiveProject() == null) {
				throw e;
			}
			if (!s.startsWith("/")) {
				s = "/" + s;
			}
			return GhidraURL.makeURL(AppInfo.getActiveProject().getProjectLocator(), s, null);
		}
	}

}
