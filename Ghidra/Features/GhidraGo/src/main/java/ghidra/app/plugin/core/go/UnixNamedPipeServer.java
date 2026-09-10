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

import java.io.*;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;

import org.unix.stat_h;

import ghidra.app.plugin.core.go.NamedPipe.MessageConsumer;
import ghidra.pty.unix.UnixErr;
import ghidra.util.Msg;

/**
 * Unix named pipe server / listener.  Uses JNA to be able to call mkfifo.
 */
public class UnixNamedPipeServer extends NamedPipeServer {
	private static final int MAX_RECV_BUFFER = UnixNamedPipe.UNIX_RAW_MAX_PIPE_MSG_LENGTH * 2;

	public UnixNamedPipeServer(File pipeFile, File lockFile, MessageConsumer msgConsumer) {
		super(pipeFile, lockFile, msgConsumer);
	}

	@Override
	public void close() {
		if (listenThread != null) {
			listenThread.interrupt();
			try {
				listenThread.join(LISTEN_THREAD_INTR_MAXWAIT_MS);
				Msg.debug(this, "Sucessfull shutdown of listen thread for " + pipeFile);
			}
			catch (InterruptedException e) {
				// don't care, we tried
				Msg.warn(this, "Failed to shutdown listen thread for " + pipeFile);
			}
		}
	}

	@Override
	protected void listenerReadLoopMethod() throws IOException {
		if (!UnixNamedPipe.isPipe(pipeFile)) {
			createUnixPipe(pipeFile);
		}

		ByteArrayOutputStream recvBuffer = new ByteArrayOutputStream();
		Thread thisThread = Thread.currentThread();

		while (!thisThread.isInterrupted()) {

			// Open the pipe in read mode because we are the 'server', AND write mode so that
			// we avoid blocking during open() waiting for a writer to connect.
			try (FileChannel fchan = FileChannel.open(pipeFile.toPath(), StandardOpenOption.READ,
				StandardOpenOption.WRITE)) {

				listenThreadReadyLatch.countDown(); // signal start() we are ready to accept connections

				// the buffer length doesn't need to match as we accumulate bytes until null-terms
				// in the recvBuffer
				byte[] bytes = new byte[UnixNamedPipe.UNIX_RAW_MAX_PIPE_MSG_LENGTH];
				ByteBuffer bb = ByteBuffer.wrap(bytes);

				while (!thisThread.isInterrupted()) {

					bb.clear();
					try {
						int bytesRead = fchan.read(bb);
						if (bytesRead == -1) {
							// should only happen when all writers have closed their end of the pipe,
							// which shouldn't happen here as we have the channel open in both
							// read and write mode so there should always be at least 1 writer (us)
							break;
						}
						if (bytesRead > 0) {
							processMessagePayload(bytes, bytesRead, recvBuffer);
							if (recvBuffer.size() > MAX_RECV_BUFFER) {
								throw new IOException(
									"Corrupted or over-length message: " + recvBuffer.size());
							}
						}
					}
					catch (ClosedByInterruptException e) {
						// normal shutdown during a blocking read
						break;
					}
				}
			}
			finally {
				if (recvBuffer.size() > 0) {
					Msg.warn(this, "Pipe listener shutdown discarding partial message: " +
						recvBuffer.toString(StandardCharsets.UTF_8));
				}
			}
		}

	}

	private void processMessagePayload(byte[] bytes, int length, ByteArrayOutputStream recvBuffer) {
		for (int i = 0; i < length; i++) {
			int nullPos = nextNullTerm(bytes, i, length);
			recvBuffer.write(bytes, i, nullPos - i);
			if (nullPos < length) {
				String msg = recvBuffer.toString(StandardCharsets.UTF_8);
				recvBuffer.reset();
				processReceivedMessage(msg);
			}
			i = nullPos;
		}
	}

	private static int nextNullTerm(byte[] bytes, int index, int length) {
		for (; index < length && bytes[index] != 0; index++) {
			// empty body
		}
		return index;
	}

	public static void createUnixPipe(File pipeFile) throws IOException {
		try (Arena arena = Arena.ofConfined()) {
			MemorySegment cs = arena.allocate(UnixErr.LAYOUT);
			int result =
				stat_h.mkfifo(                              // args...
					cs,                                     // to capture errno 
					arena.allocateFrom(pipeFile.getPath()), // fifo path
					0600                                    // mode, octal perms "rw-----"
				);
			if (result != 0) {
				int errno = (int) UnixErr.ERRNO.get(cs, 0);
				throw new IOException("Failed to create pipe %s: %d (%s)".formatted(pipeFile, errno,
					UnixErr.strerror(errno)));
			}
		}
	}

}
