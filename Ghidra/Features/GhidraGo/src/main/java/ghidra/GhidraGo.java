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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import docking.DockingWindowManager;
import docking.framework.DockingApplicationConfiguration;
import generic.jar.ResourceFile;
import ghidra.GhidraGoWaitDialog.WAIT_DIALOG_RESULT;
import ghidra.app.plugin.core.go.NamedPipe;
import ghidra.framework.*;
import ghidra.framework.main.ApplicationPidFile;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.*;
import ghidra.util.exception.TimeoutException;
import utility.application.ApplicationLayout;

/**
 * <h1>GhidraGo Client</h1>
 * <p>The first argument is expected to be non-null and a valid {@link GhidraURL}</p>
 * <p>If the {@link GhidraURL} is valid, the URL is processed in an existing Ghidra, or
 * a new Ghidra is started and used to process the URL.</p>
 * <p>A valid {@link GhidraURL} in this case must be pointing to a remote (shared project) 
 * Program.</p>
 * <p>In the event that a Ghidra is running and does not have an active project, the URL cannot be 
 * processed.</p>
 */
public class GhidraGo implements GhidraLaunchable {

	/// Used to prevent multiple processes from starting a new Ghidra at the
	/// same time
	private static final String LAUNCH_LOCK_FILENAME = "ghidrago.launch.lock";
	private static final Duration LAUNCH_MAXWAIT = Duration.ofMillis(20000);
	private static final Duration READY_MAXWAIT = Duration.ofMillis(20000);
	private static final Duration QUICK_SEND_MAXWAIT = Duration.ofMillis(1000);
	private static final Duration SEND_MAXWAIT = Duration.ofMillis(5000);
	private static final Duration READY_POLL_SLEEP = Duration.ofMillis(100);

	private NamedPipe pipe;
	private GhidraGoWaitDialog dialog;
	private long lastUserCheckMS;

	/**
	 * Initializes a new GhidraGoSender and processes the {@link GhidraURL}
	 * @param layout the layout passed from main.Ghidra
	 * @param args the CLI args passed to GhidraGo. args should contain a single {@link GhidraURL}.
	 * @throws Exception in the event of an error
	 */
	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		if (args == null || args.length == 0 || args[0].isBlank()) {
			usage(null);
			return;
		}

		ghidra.framework.protocol.ghidra.Handler.registerHandler();
		URL ghidraUrl;
		try {
			ghidraUrl = GhidraURL.toURL(args[0]);
			//ghidraUrl = new URI(args[0]).toURL();
			GhidraURL.getProjectURL(ghidraUrl); // perform Ghidra URL validation only
		}
		catch (IllegalArgumentException e) {
			usage("Bad URL: " + args[0]);
			return;
		}

		pipe = getGhidraGoNamedPipe(layout);

		try {
			// Check if we can quickly connect to the pipe without starting a GUI to prompt the user
			if (!ApplicationPidFile.getRunningPids(layout).isEmpty() && pipe.hasListener()) {
				pipe.writeMessage(ghidraUrl.toString(), QUICK_SEND_MAXWAIT);
				System.out
						.println("Successfully sent URL: [%s] via [%s]".formatted(ghidraUrl, pipe));
				return; // quick success, no gui needed
			}
		}
		catch (IOException e) {
			// some kind of problem, fall thru and try again after starting gui
		}

		ApplicationConfiguration configuration = null;
		boolean sendSuccess = false;
		try {
			if (!Application.isInitialized()) {
				System.setProperty(ApplicationProperties.APPLICATION_NAME_PROPERTY, "GhidraGo");
				configuration = new DockingApplicationConfiguration();
				Application.initializeApplication(layout, configuration);
			}

			lastUserCheckMS = System.currentTimeMillis();
			startGhidraIfNeeded(layout);

			pipe.writeMessage(ghidraUrl.toString(), SEND_MAXWAIT);
			sendSuccess = true;
			Msg.info(this, "Successfully sent URL: [%s] via [%s]".formatted(ghidraUrl, pipe));
		}
		catch (UserTerminatedWaitException e) {
			// no need to show user error, they already decided to terminate the launch / wait
			Msg.error(this, "Failed to start Ghidra from GhidraGo: " + e.getMessage(),
				e.getCause());
		}
		catch (TimeoutException | IOException e) {
			logOrShowError("GhidraGo Start Ghidra Exception",
				"Failed to start Ghidra from GhidraGo: " + e.getMessage(), e.getCause());
		}
		catch (Exception e) {
			logOrShowError("GhidraGo Exception", "An unexpected exception occurred in GhidraGo", e);
		}
		finally {
			// if configuration is null, probably running inside a test
			if (configuration != null) {
				// calling System.exit explicitly is necessary, otherwise the Loading... screen
				// persists instead of closing when complete.
				System.exit(sendSuccess ? 0 : -1);
			}
			else {
				// try to shut down nicely since we are not the primary application
				if (dialog != null) {
					GhidraGoWaitDialog localDlg = dialog;
					Swing.runNow(() -> localDlg.close());
					dialog = null;
				}
			}
		}
	}

	private void usage(String extraMessage) {
		System.err.println("""
				USAGE: ghidraGo <ghidraURL>

				Ghidra URL Forms (ghidraURL):
				  ghidra://<hostname>[:<port>]/<repo-name>[/<folder-path>[/<program-name>]]
				  ghidra:/[<local-dirpath>/]<project-name>[?/<folder-path>[/<program-name>]]
				""");
		if (extraMessage != null && !extraMessage.isEmpty()) {
			System.err.println();
			System.err.println(extraMessage);
			System.err.println();
		}
	}

	private void logOrShowError(String errorTitle, String errorMessage, Throwable e) {
		if (SystemUtilities.isInHeadlessMode()) {
			Msg.error(this, errorMessage, e);
		}
		else {
			Swing.runNow(() -> Msg.showError(this, null, errorTitle, errorMessage, e));
		}
	}

	private void ensureDialog(String message, Duration waitDuration, long elapsedMS) {
		long now = System.currentTimeMillis();

		if (dialog != null && dialog.getResult() == WAIT_DIALOG_RESULT.WAIT) {
			lastUserCheckMS = now;
			GhidraGoWaitDialog localDlg = dialog;
			Swing.runNow(() -> localDlg.close());
			dialog = null;
		}
		if (lastUserCheckMS + waitDuration.toMillis() > now) {
			return;
		}

		if (dialog == null) {
			GhidraGoWaitDialog newDialog = Swing.runNow(() -> new GhidraGoWaitDialog());
			dialog = newDialog;
			Swing.runLater(() -> DockingWindowManager.showDialog(null, newDialog));
		}
		dialog.updateMessage(message, elapsedMS);
	}

	private boolean shouldTerminateWait() {
		WAIT_DIALOG_RESULT result;
		if (dialog == null || (result = dialog.getResult()) == null) {
			return false;
		}

		return result == WAIT_DIALOG_RESULT.DO_NOT_WAIT;
	}

	private void startGhidraIfNeeded(GhidraApplicationLayout layout)
			throws TimeoutException, IOException {

		if (pipe.hasListener()) {
			return;
		}

		File pidsDir = ApplicationPidFile.getPidsDir(layout);
		File launchLock = new File(pidsDir, LAUNCH_LOCK_FILENAME);

		// Ensure only 1 process tries to launch a Ghidra simultaneously
		// Note: if unable to acquire the launch lock within this timeout this ghidraGo instance
		// will exit with an error.  If it is common for multiple ghidraGo instances to be spawned
		// at the same time, it may be desirable to wait indefinitely.
		NamedPipe.withLock(launchLock, LAUNCH_MAXWAIT, () -> {

			List<Long> runningPids = ApplicationPidFile.getRunningPids(layout);
			if (runningPids.isEmpty()) {
				String ghidraRunPath = getGhidraLaunchScript(layout);

				Msg.info(this, "Starting new Ghidra using ghidraRun script at " + ghidraRunPath);
				Process proc = new ProcessBuilder(ghidraRunPath).start();

				long launchStartMS = System.currentTimeMillis();

				do {
					try {
						if (proc.waitFor(READY_POLL_SLEEP)) {
							int exitVal = proc.exitValue();
							if (exitVal == 0) {
								break; // success
							}
							throw new IOException("Failed to start Ghidra %s, exit value %d"
									.formatted(ghidraRunPath, exitVal));
						}
					}
					catch (InterruptedException ie) {
						throw new IOException("Error waiting for Ghidra launch", ie);
					}

					long elapsedMS = System.currentTimeMillis() - launchStartMS;
					ensureDialog("Waiting for Ghidra to start", LAUNCH_MAXWAIT, elapsedMS);

					if (shouldTerminateWait()) {
						throw new UserTerminatedWaitException(
							"Failed to start Ghidra timely, user choose to stop waiting");
					}
				}
				while (true);
			}
			else {
				Msg.info(this, "Ghidra already running: %s".formatted(runningPids));
			}

			// the ghidraRun process has been successfully executed, now we wait for Ghidra to
			// start processing stuff

			Msg.info(this, "Waiting for Ghidra to be ready");
			long waitStartMS = System.currentTimeMillis();
			while (!pipe.hasListener()) {
				long elapsedMS = System.currentTimeMillis() - waitStartMS;
				ensureDialog("Waiting for Ghidra to be ready", READY_MAXWAIT, elapsedMS);
				if (shouldTerminateWait()) {
					throw new UserTerminatedWaitException(
						"Failed to start Ghidra, has not started pipe yet");
				}

				try {
					Thread.sleep(READY_POLL_SLEEP.toMillis());
				}
				catch (InterruptedException e) {
					throw new IOException(e);
				}
			}
		});

		//
		// There should now be a Ghidra listening on the other end of the IPC pipe
		//
	}

	private Path getGhidraLaunchScriptDir(GhidraApplicationLayout layout) {
		ResourceFile file = layout.getApplicationRootDirs().stream().findFirst().get();
		return SystemUtilities.isInDevelopmentMode()
				? Path.of(file.getAbsolutePath(), "RuntimeScripts")
				: Path.of(file.getParentFile().getAbsolutePath());
	}

	private String getGhidraLaunchScript(GhidraApplicationLayout layout) {
		return getGhidraLaunchScriptDir(layout)
				.resolve(Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS
						? "ghidraRun.bat"
						: "ghidraRun")
				.toString();
	}

	public static class UserTerminatedWaitException extends IOException {
		public UserTerminatedWaitException(String message) {
			super(message);
		}
	}

	public static File getGlobalConfigDir(ApplicationLayout layout) {
		// intentionally co-located in the parent directory of the specific version config dir,
		// same as "lastrun"
		return layout.getUserSettingsDir().getParentFile();
	}

	public static NamedPipe getGhidraGoNamedPipe(ApplicationLayout layout) {
		// Use a prefix for the global pipe name if in testing mode so tests won't conflict with
		// a running Ghidra.  (mainly on Windows with its global pipe \\.\pipe\ location)
		// Note: this means a GhidraGo listener running in a test will be connected to a different
		// pipe than a manually executed ghidraGo sender (or vice versa).
		String pipeNamePrefix = layout instanceof GhidraTestApplicationLayout ? "testmode_" : "";
		return NamedPipe.newGlobalConfigPipe(pipeNamePrefix + "ghidrago",
			getGlobalConfigDir(layout));
	}

}
