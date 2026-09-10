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
package ghidra.framework.main;

import java.io.*;
import java.nio.channels.*;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

import utility.application.ApplicationLayout;

/**
 * Represents this application's lively-ness to other Ghidra processes / helpers.
 * <p>
 * An application should create a single instance via {@link #forThisProcess(ApplicationLayout)}
 * early during startup, and keep it until shutdown, and then call {@link #close()}.
 * <p>
 * Applications that wish to know if there is an already running Ghidra before launching a new one
 * may query {@link #getRunningPids(ApplicationLayout)}.
 */
public class ApplicationPidFile implements Closeable {

	/**
	 * {@return the File path to a globally located directory where pid files should be located.
	 * 'Globally located' means not tied to a specific Ghidra version.  Never null.}
	 * 
	 * @param layout {@link ApplicationLayout} with information about directory paths
	 * @throws IOException if error creating a missing pids directory
	 */
	public static File getPidsDir(ApplicationLayout layout) throws IOException {
		File settingsDir = layout.getUserSettingsDir();
		File pidsDir = new File(settingsDir.getParentFile(), "pids");
		if (!pidsDir.isDirectory() && !pidsDir.mkdir()) {
			throw new IOException("Failed to create 'pids' directory: " + pidsDir);
		}
		return pidsDir;
	}

	/**
	 * {@return an ApplicationPidFile instance for this application's pid}
	 * @param layout {@link ApplicationLayout} with information about directory paths
	 * @throws IOException if error manipulating pid files
	 */
	public static ApplicationPidFile forThisProcess(ApplicationLayout layout) throws IOException {
		File pidsDir = getPidsDir(layout);

		long myPid = ProcessHandle.current().pid();
		File pidFile = new File(pidsDir, "%d".formatted(myPid));

		FileChannel pidFileChannel;
		try {
			// the channel and lock objects are intentionally not released for the entire lifetime
			// of the application
			pidFileChannel = FileChannel.open(pidFile.toPath(), StandardOpenOption.CREATE_NEW,
				StandardOpenOption.WRITE);
		}
		catch (IOException e) {
			throw new IOException("Failed to open pid file: " + pidFile);
		}

		FileLock pidFileLock;
		try {
			pidFileLock = pidFileChannel.tryLock();
		}
		catch (IOException | OverlappingFileLockException e) {
			pidFileLock = null;
		}

		if (pidFileLock != null) {
			return new ApplicationPidFile(pidFile, pidFileChannel, pidFileLock);
		}

		try {
			pidFileChannel.close();
		}
		catch (IOException e) {
			// ignore
		}
		throw new IOException("Failed to lock pid file: " + pidFile);
	}

	/**
	 * {@return a list of pids of the currently running Ghidra processes}
	 * @param layout {@link ApplicationLayout} with information about directory paths
	 */
	public static List<Long> getRunningPids(ApplicationLayout layout) {
		List<Long> results = new ArrayList<>();
		try {
			File pidsDir = getPidsDir(layout);
			File[] pidFiles = pidsDir != null ? pidsDir.listFiles() : null;
			if (pidFiles == null || pidFiles.length == 0) {
				return results;
			}

			for (File otherPidFile : pidFiles) {
				try {
					if (otherPidFile.length() != 0) {
						continue; // skip, they should be empty files
					}
					long pid = Long.parseLong(otherPidFile.getName());

					try (FileChannel fchan = FileChannel.open(otherPidFile.toPath(),
						StandardOpenOption.READ, StandardOpenOption.WRITE)) {

						FileLock lock;
						try {
							lock = fchan.tryLock();
						}
						catch (OverlappingFileLockException e) {
							// treat the same as tryLock() returning null
							lock = null;
						}

						if (lock == null) {
							// success, the pid file is locked, meaning the ghidra is running
							results.add(pid);
							continue;
						}

						// if we were able to lock the file we should delete it to clean it up
						// since it is a leftover
						lock.close();
						fchan.close();
						otherPidFile.delete();
					}
					catch (IOException e) {
						// don't care
					}
				}
				catch (NumberFormatException e) {
					// ignore
				}
			}
		}
		catch (IOException e) {
			// ignore
		}
		return results;
	}

	private File pidFile;
	private FileChannel pidFileChannel;
	@SuppressWarnings("unused")
	private FileLock pidFileLock;

	private ApplicationPidFile(File pidFile, FileChannel pidFileChannel, FileLock pidFileLock) {
		this.pidFile = pidFile;
		this.pidFileChannel = pidFileChannel;
		this.pidFileLock = pidFileLock;
	}

	@Override
	public void close() {
		if (pidFileChannel != null) {
			try {
				pidFileChannel.close();
			}
			catch (IOException e) {
				// ignore
			}
			pidFileChannel = null;
			pidFileLock = null;
		}
		if (pidFile != null) {
			pidFile.delete();
			pidFile = null;
		}
	}

}
