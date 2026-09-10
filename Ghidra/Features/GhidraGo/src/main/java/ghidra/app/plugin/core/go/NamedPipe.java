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

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import ghidra.framework.OperatingSystem;
import ghidra.util.exception.TimeoutException;

/**
 * Abstract base class with common functionality of identifying a named pipe and sending string
 * messages via the pipe.
 * <p>
 * Low-level OS named pipes are paired with a companion lock file to help control multiple processes
 * simultaneously trying to become the listener.
 */
public abstract class NamedPipe {

	private static final Duration HASLISTENER_CHECK_TIMEOUT = Duration.ofMillis(50);

	/**
	 * Creates a named pipe in a platform specific, global, location.
	 * 
	 * @param pipeName name of the pipe
	 * @param globalConfigDir location of the ghidra 'global' configuration directory
	 * @return new {@link NamedPipe}
	 */
	public static NamedPipe newGlobalConfigPipe(String pipeName, File globalConfigDir) {
		File pipeFile = OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS
				? WinNamedPipe.createPipeFilepath("ghidra_namedpipe_" + pipeName)
				: new File(globalConfigDir, pipeName);

		File lockFile = new File(globalConfigDir, pipeName + ".lock");

		return newPipe(pipeFile, lockFile);
	}

	/**
	 * Creates a platform specific named pipe.
	 * 
	 * @param pipeFile location of the named pipe
	 * @param lockFile location of the lock file
	 * @return new platform specific {@link NamedPipe} instance
	 */
	public static NamedPipe newPipe(File pipeFile, File lockFile) {
		return OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS
				? new WinNamedPipe(pipeFile, lockFile)
				: new UnixNamedPipe(pipeFile, lockFile);
	}

	public static final int MAX_PIPE_MSG_LENGTH =
		Math.min(UnixNamedPipe.UNIX_MAX_PIPE_MSG_LENGTH, WinNamedPipe.WIN_MAX_PIPE_MSG_LENGTH);
	protected static final int MAX_SEND_RETRY_COUNT = 100;

	protected File pipeFile;
	protected File lockFile;

	protected NamedPipe(File pipeFile, File lockFile) {
		this.pipeFile = pipeFile;
		this.lockFile = lockFile;
	}

	/**
	 * {@return boolean true if the OS-level named pipe exists, otherwise false}
	 */
	public abstract boolean pipeObjectExists();

	/**
	 * {@return a platform specific {@link NamedPipeServer} instance tied to this instance's
	 * location}
	 * 
	 * @param msgConsumer callback string consumer
	 */
	public abstract NamedPipeServer createServer(MessageConsumer msgConsumer);

	/**
	 * Writes a string message to the pipe.  The server on the other side of the pipe may or may
	 * not be listening, and there is no strong guarantee that the message will be delivered.
	 * <p>
	 * Note: the Windows named pipe implementation does not allow messages to silently disappear,
	 * whereas the Unix named pipe implementation may allow messages to disappear if there is no
	 * listener. 
	 * <p>
	 * The message length is limited to {@link #MAX_PIPE_MSG_LENGTH} (4096'ish) bytes.
	 * 
	 * @param message string message to send
	 * @param timeout max {@link Duration} to wait (for retries and other connection overhead) when
	 * 	attempting to send the message 
	 * @throws IOException if error writing the message
	 */
	public abstract void writeMessage(String message, Duration timeout) throws IOException;

	/**
	 * {@return boolean true if it appears there is a server listening to the other end of the pipe}
	 * @throws IOException if error checking the pipe
	 */
	public boolean hasListener() throws IOException {
		try {
			withLock(lockFile, HASLISTENER_CHECK_TIMEOUT, () -> {
				// if we can get the lock, there isn't an active server/listener
			});
			return false;
		}
		catch (TimeoutException e) {
			// success, we failed to get a lock, there should be a listener on the other
			// end of the pipe (if the pipe object exists)
			return pipeObjectExists();
		}
	}

	@Override
	public String toString() {
		return pipeFile.toString();
	}


	public interface CheckedRunnable<E extends Throwable> {
		void run() throws E;
	}

	public interface MessageConsumer {
		void accept(String message) throws IOException;
	}

	/**
	 * Performs an action while holding a lock on a lock file.
	 * 
	 * @param <E> type of Exception thrown by the action callback
	 * @param lockFile File to lock
	 * @param timeout {@link Duration} to wait to acquire the lock, or null for unconditional
	 * blocking while waiting
	 * @param r callback action to execute
	 * @throws E if error thrown by the callback
	 * @throws IOException if error manipulating the lock file
	 * @throws TimeoutException if unable to acquire lock within timeout specified
	 */
	public static <E extends Throwable> void withLock(File lockFile, Duration timeout,
			CheckedRunnable<E> r) throws E, IOException, TimeoutException {

		long timeoutMS = timeout != null ? timeout.toMillis() : Long.MAX_VALUE;
		long startts = System.currentTimeMillis();
		long maxts = timeout != null ? startts + timeoutMS : Long.MAX_VALUE;
		long sleepMS = Math.min(timeoutMS, 100); // 100ms is largest sleep-per-retry interval
		long lockerPid = -1;

		RandomAccessFile raf;
		try {
			raf = new RandomAccessFile(lockFile, "rw");
		}
		catch (IOException e) {
			throw new LockIOException("Failed to open lock file " + lockFile, e);
		}

		try (raf) {
			FileChannel fchan = raf.getChannel();
			while (true) {
				FileLock lock = null;
				try {
					// Lock an unused/non-existent portion of the file to avoid read/write errors
					// by other processes on Windows jvms
					lock = timeout != null
							? fchan.tryLock(LOCKFILE_LOCK_OFFSET, 1, false)
							: fchan.lock(LOCKFILE_LOCK_OFFSET, 1, false);
				}
				catch (OverlappingFileLockException e) {
					// same as lock() failing, fallthru with lock == null
				}
				catch (IOException e) {
					throw new LockIOException("Failed to lock region of " + lockFile, e);
				}

				if (lock == null) {
					// Failed to get lock.  We may try again, or give up

					if (timeout == null) {
						// failed to get lock before something else shut us down
						break;
					}

					// failed to acquire lock, sleep and try again
					long remaining = maxts - System.currentTimeMillis();
					if (remaining < 0) {
						// failed to acquire lock within allowed time, give up
						break;
					}

					lockerPid = tryReadLockerInfo(raf);
					Thread.sleep(sleepMS);
					continue; // try lock again
				}

				try {
					writeLockerInfo(raf);
					r.run();
					raf.setLength(0);
					return;
				}
				finally {
					lock.close();
				}

			}
			throw new TimeoutException("Timeout waiting to lock [%s], locker's pid: [%s]"
					.formatted(lockFile, lockerPid != -1 ? Long.toString(lockerPid) : "unknown"));
		}
		catch (InterruptedException e) {
			throw new IOException("Error locking file [%s]".formatted(lockFile), e);
		}
	}

	private static final int LOCKFILE_LOCK_OFFSET = 1_000_000;

	private static void writeLockerInfo(RandomAccessFile raf) throws LockIOException {
		try {
			long mypid = ProcessHandle.current().pid();
			raf.setLength(0);
			raf.write("%d\n".formatted(mypid).getBytes(StandardCharsets.UTF_8));
		}
		catch (IOException e) {
			throw new LockIOException("Failed to write lock info", e);
		}
	}

	private static long tryReadLockerInfo(RandomAccessFile raf) {
		try {
			byte[] buffer = new byte[64];
			raf.seek(0);
			int bytesRead = raf.read(buffer);
			if (bytesRead > 0 && buffer[bytesRead - 1] == '\n') {
				// low-tech verification of the data by checking for a trailing \n
				String s = new String(buffer, 0, bytesRead - 1, StandardCharsets.UTF_8);
				long lockersPid = Long.parseLong(s);
				return lockersPid;
			}
		}
		catch (IOException | NumberFormatException e) {
			// fall thru
		}
		return -1;
	}

	public static class LockIOException extends IOException {
		public LockIOException(String msg, Throwable th) {
			super(msg, th);
		}
	}

}
