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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.OperatingSystem;

public class WinNamedPipeTest extends AbstractGenericTest {

	File tmpDir;
	NamedPipe np;

	@Before
	public void setUp() throws IOException {
		assumeTrue(OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS);
		tmpDir = createTempDirectory("namedpipes");
		np = new WinNamedPipe(WinNamedPipe.createPipeFilepath("namedpipe"),
			new File(tmpDir, "namedpipe.lock"));
	}

	@Test(timeout = 5000)
	public void testNoFifo() throws IOException {
		try {
			assertFalse(np.hasListener());
			np.writeMessage("test message", null);
			fail();
		}
		catch (IOException e) {
			// good
		}
	}

	@Test(timeout = 5000)
	public void testNoServer() throws IOException, InterruptedException {
		List<String> receivedMessages = Collections.synchronizedList(new ArrayList<>());
		NamedPipeServer nps = np.createServer(s -> receivedMessages.add(s));
		nps.start(Duration.ofMillis(1000));
		nps.close();

		assertFalse(np.hasListener());

		try {
			np.writeMessage("test message", null);
			fail();
		}
		catch (IOException e) {
			// good
		}

		Thread.sleep(1000); // hacky but necessary since we're testing a shutdown/closed listener
		assertTrue(receivedMessages.isEmpty());

	}

	@Test(timeout = 30000)
	public void testSendRecv() throws InterruptedException {
		// Use several threads to spam writing messages to the named pipe.
		// Check that all sent messages were received by the server, and vice versa.
		final int spamCount = 10000;

		List<String> receivedMessages =
			Collections.synchronizedList(new ArrayList<>(spamCount * 3));

		NamedPipeServer nps = np.createServer(s -> receivedMessages.add(s));
		if (!nps.start(Duration.ofMillis(1000))) {
			fail();
		}

		List<String> sentMessages = Collections.synchronizedList(new ArrayList<>(spamCount * 3));

		Thread t1 = new Thread(() -> spamMessages(sentMessages, "thread 1 spam", spamCount));
		Thread t2 =
			new Thread(() -> spamMessages(sentMessages, "thread 2 extra longer spam", spamCount));
		Thread t3 = new Thread(
			() -> spamMessages(sentMessages,
				"thread 3 extra extra longer spamxxxxxxxxxxxxxxxxxxxxxxxx", spamCount));

		t1.start();
		t2.start();
		t3.start();

		t1.join();
		t2.join();
		t3.join();

		nps.close();

		assertEquals(spamCount * 3, sentMessages.size());

		Set<String> sentMessageCopy = new HashSet<>(sentMessages);
		for (String recvdMessage : receivedMessages) {
			if (!sentMessageCopy.contains(recvdMessage)) {
				fail("Received a string that was not sent: " + recvdMessage);
			}
		}
		Set<String> recvMessagesSet = new HashSet<>(receivedMessages);
		sentMessageCopy.removeAll(recvMessagesSet);

		assertTrue("Messages sent but not received: " + sentMessageCopy.size(),
			sentMessageCopy.isEmpty());

		Thread.sleep(10000);
	}

	private void spamMessages(List<String> sentMessages, String prefix, int count) {
		for (int i = 0; i < count; i++) {
			String message = prefix + "%d".formatted(i);
			try {
				np.writeMessage(message, Duration.ofMillis(100));
				sentMessages.add(message);
			}
			catch (IOException e) {
				failWithException("Failed to send message to namedpipe", e);
				break;
			}
		}
	}

	@Test
	public void testLongMessages() throws IOException {
		List<String> receivedMessages = Collections.synchronizedList(new ArrayList<>());

		NamedPipeServer nps = np.createServer(s -> receivedMessages.add(s));
		if (!nps.start(Duration.ofMillis(1000))) {
			fail();
		}

		np.writeMessage("X".repeat(WinNamedPipe.WIN_MAX_PIPE_MSG_LENGTH), Duration.ZERO);

		try {
			np.writeMessage("X".repeat(WinNamedPipe.WIN_MAX_PIPE_MSG_LENGTH + 1), Duration.ZERO);
			fail();
		}
		catch (IOException e) {
			// good
		}

		nps.close();

		assertEquals(1, receivedMessages.size());
		assertEquals("X".repeat(WinNamedPipe.WIN_MAX_PIPE_MSG_LENGTH), receivedMessages.get(0));
	}

}
