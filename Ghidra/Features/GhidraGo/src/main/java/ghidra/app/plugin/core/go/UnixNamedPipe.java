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

import static java.nio.file.StandardOpenOption.*;

import java.io.*;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Unix named pipe implementation.  Uses java native to be able to call mkfifo.
 * <p>
 * Writing messages to the pipe are not guaranteed to be delivered if a listener is not connected
 * to the other end of the pipe.
 * <p>
 * Messages written to the pipe are delimited with a '\0' null term byte to separate adjacent 
 * messages that the listener will read.
 */
public class UnixNamedPipe extends NamedPipe {
	public static final int UNIX_RAW_MAX_PIPE_MSG_LENGTH = 4096;
	public static final int UNIX_MAX_PIPE_MSG_LENGTH =
		UNIX_RAW_MAX_PIPE_MSG_LENGTH - 1 /* needs a null term*/;

	public UnixNamedPipe(File pipeFile, File lockFile) {
		super(pipeFile, lockFile);
	}

	@Override
	public boolean pipeObjectExists() {
		return isPipe(pipeFile);
	}

	public static boolean isPipe(File pipeFile) {
		return pipeFile.exists() && pipeFile.isFile() == false && pipeFile.isDirectory() == false;
	}

	@Override
	public NamedPipeServer createServer(MessageConsumer msgConsumer) {
		return new UnixNamedPipeServer(pipeFile, lockFile, msgConsumer);
	}

	@Override
	public void writeMessage(String message, Duration timeout) throws IOException {
		if (!pipeObjectExists()) {
			throw new FileNotFoundException("Pipe does not exist: " + pipeFile);
		}
		byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
		byte[] terminatedBytes = new byte[bytes.length + 1];
		System.arraycopy(bytes, 0, terminatedBytes, 0, bytes.length); // we get a trailing \0 for free

		if (terminatedBytes.length > UNIX_RAW_MAX_PIPE_MSG_LENGTH) {
			throw new IOException("Unable to write overly long message to pipe, length=%d"
					.formatted(terminatedBytes.length));
		}

		Path pipeFilePath = pipeFile.toPath();
		long endMS = timeout != null ? System.currentTimeMillis() + timeout.toMillis() : 0;
		int retryCount = 0;
		do {
			// Note: hacky code to avoid blocking during open().
			//
			// If the pipe is open()ed only in WRITE mode, we will block (without ability to intr)
			// until a reader opens the pipe.  This is not desirable.
			//
			// If we open() the pipe in both WRITE and READ mode, we can avoid blocking, and as long
			// as we don't read(), anything written will go to a reader on the other end of the pipe.
			// If there isn't a reader on the other end of the pipe, when we close() our handle, the
			// contents of the pipe will be silently lost.  This also is not desirable.  Relying
			// on the status of the file lock to signal that there is a reader on the other end of
			// the pipe can avoid most problems, but its not perfect.

			try (FileChannel fchan = FileChannel.open(pipeFilePath, READ, WRITE)) {

				OutputStream chanOS = Channels.newOutputStream(fchan);
				chanOS.write(terminatedBytes);
				chanOS.flush();
				fchan.close();
				return;
			}
			catch (IOException e) {
				// probably got a broken pipe error if the server happened to close its handle from
				// a different process's connection right when we connected.
				// Retry opening the pipe
			}
		}
		while (retryCount++ < MAX_SEND_RETRY_COUNT && System.currentTimeMillis() < endMS);

		throw new IOException("Unable to write message");
	}

}
