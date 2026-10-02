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

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import ghidra.app.plugin.core.go.NamedPipe.MessageConsumer;
import ghidra.util.Msg;
import ghidra.util.exception.TimeoutException;

/**
 * Abstract base class with common functionality for listening to named pipes and handling string
 * messages received via the pipe.
 */
public abstract class NamedPipeServer implements Closeable {

	protected static final int LISTEN_THREAD_INTR_MAXWAIT_MS = 10;

	protected File pipeFile;
	protected File lockFile;
	protected Thread listenThread;
	protected MessageConsumer msgConsumer;
	protected CountDownLatch listenThreadReadyLatch = new CountDownLatch(1);

	public NamedPipeServer(File pipeFile, File lockFile, MessageConsumer msgConsumer) {
		this.pipeFile = pipeFile;
		this.lockFile = lockFile;
		this.msgConsumer = msgConsumer;
	}

	/**
	 * Starts the background listening thread for this named pipe.
	 * <p>
	 * The background listening thread will block indefinitely waiting to gain the lock file,
	 * and then will open the native pipe and begin listening.
	 * <p>
	 * Messages received via the pipe will be handed off to the supplied MessageConsumer.
	 * <p>
	 * The background thread continues to run until interrupted via a call to {@link #close()}.
	 * It will then release the OS level pipe and the exclusive file lock and then terminate.
	 * 
	 * @param readyWaitTimeout max amount of time to wait for the background thread to report
	 * success in acquiring the pipe and starting listening.
	 *  
	 * @return boolean true if the listen thread started listening to the pipe before the
	 * readyWait timeout expires, otherwise false.  Returning true only
	 * indicates that the server gained immediate control of the named pipe.
	 */
	public boolean start(Duration readyWaitTimeout) {
		listenThread = new Thread(this::listenerThreadMethod, "Pipe Server " + pipeFile.getName());
		listenThread.setDaemon(true);
		listenThread.start();
		try {
			listenThreadReadyLatch.await(readyWaitTimeout.toMillis(), TimeUnit.MILLISECONDS);
			return true;
		}
		catch (InterruptedException e) {
			return false;
		}
	}

	@Override
	public abstract void close();

	protected void listenerThreadMethod() {
		try {
			Msg.debug(this, "Starting Pipe Server Thread " + pipeFile);

			// Wait indefinitely to get an exclusive lock on the .lock file, indicating that we
			// are the single owner(reader) of the pipe.
			NamedPipe.withLock(lockFile, null, () -> {
				Msg.debug(this, "Pipe lock acquired for " + pipeFile);

				listenerReadLoopMethod();

				Msg.debug(this, "Pipe listener thread %s shutdown".formatted(pipeFile));
			});
		}
		catch (IOException | TimeoutException e) {
			Msg.error(this, "Pipe listener thread %s error".formatted(pipeFile), e);
		}
		finally {
			Msg.debug(this, "Pipe listener thread %s done".formatted(pipeFile));
		}
	}

	/**
	 * Derived implementations need to provide an implementation of this method that opens the
	 * named pipe and loops, reading messages from the pipe and submitting them to
	 * {@link #processReceivedMessage(String)}, until the thread is interrupted.
	 * 
	 * @throws IOException if error opening, reading from named pipe
	 */
	protected abstract void listenerReadLoopMethod() throws IOException;

	protected void processReceivedMessage(String msg) {
		try {
			msgConsumer.accept(msg);
		}
		catch (IOException e) {
			Msg.error(this, "Pipe listener consumer failed", e);
		}
	}

}
