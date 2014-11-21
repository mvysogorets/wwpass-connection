package com.wwpass.connection;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.codec.DecoderException;
import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import com.google.code.tempusfugit.concurrency.ConcurrentTestRunner;
import com.wwpass.connection.exceptions.WWPassProtocolException;
import com.wwpass.connection.util.TestUtils;

/**
 *
 * @copyright (c) WWPass Corporation, 2013
 * @author Stanislav Panyushkin <s.panyushkin@wwpass.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
//@RunWith(ConcurrentTestRunner.class)
public class WWPassConnectionTest extends Assert {

	private static final byte[] BYTE_DATA = {0,1,-2,3,-4,-5,6};
	
	private static String certFile;
	private static String keyFile;
	private static byte[] imgData;
	
	private static TestUtils testUtils;
	private static List<String> tickets = new ArrayList<String>();
	private static WWPassConnection conn = null;
	
	static {
		try {
			Properties props = new Properties();
			props.load(ClassLoader.class.getResourceAsStream("/setup.properties"));

			certFile = props.getProperty("CERT_FILE");
			keyFile = props.getProperty("KEY_FILE");
			
			InputStream is = ClassLoader.class.getResourceAsStream("/img/bytes.jpg");
			byte[] buffer = new byte[8192];
		    int bytesRead;
		    ByteArrayOutputStream output = new ByteArrayOutputStream();
		    while ((bytesRead = is.read(buffer)) != -1)
		    {
		        output.write(buffer, 0, bytesRead);
		    }
		    imgData = output.toByteArray();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@BeforeClass
	public static void setup() throws GeneralSecurityException, IOException,
			InterruptedException {

		conn = new WWPassConnection(certFile, keyFile);
		testUtils = new TestUtils();
		String[] ticket = testUtils.getTicket().split(" ", 2);
		if ("200".equals(ticket[0])) {
			String newticket = conn.putTicket(ticket[1], 300);
			tickets.add(newticket);
			tickets.add(ticket[1]);
			tickets.add("wrong ticket format");
			tickets.add("");
		} else {
			throw new IllegalArgumentException(
					"Error occured while getting user ticket. Error code: "
							+ ticket[0]);
		}

		conn.writeData(tickets.get(0), "");
	}

    @AfterClass
    public static void clean() {
        System.gc();
    }

	@Test
	public void testGetTicket() throws WWPassProtocolException, UnsupportedEncodingException, IOException, InterruptedException {
		
		// Normal case 
		String ticket = conn.getTicket();
		String[] newTicket = testUtils.authenticateTicket(ticket).split(" ", 2);
		if ("200".equals(newTicket[0])) {
			try {
				conn.getPUID(ticket);
			} catch (WWPassProtocolException e) {
				fail("Expected no exception, but catch " + e.getMessage());
			}
		} else {
			throw new IllegalArgumentException(
					"Error occured while getting user ticket. Error code: "
							+ newTicket[0] + ". Message: " + newTicket[1]);
		}
		
		// Custom TTL case
		ticket = conn.getTicket(3);
		Thread.sleep(5000);
		newTicket = testUtils.authenticateTicket(ticket).split(" ", 2);
		assertTrue("Expected error code 400, but returned: " + newTicket[0], 
					"400".equals(newTicket[0]));
		
		// Custom TTL and "p" auth_type case
		ticket =conn.getTicket("p", 3);
		Thread.sleep(3000);
		newTicket = testUtils.authenticateTicketWithP(ticket).split(" ", 2);
		assertTrue("Expected error code 400, but returned: " + newTicket[0], 
				"400".equals(newTicket[0]));
		
		// "p" auth_type case
		ticket = conn.getTicket("p");
		newTicket = testUtils.authenticateTicketWithP(ticket).split(" ", 2);
		if ("200".equals(newTicket[0])) {
			try {
				conn.getPUID(ticket);
			} catch (WWPassProtocolException e) {
				fail("Expected no exception, but catch " + e.getMessage());
			}
		} else {
			throw new IllegalArgumentException(
					"Error occured while getting user ticket. Error code: "
							+ newTicket[0] + ". Message: " + newTicket[1]);
		}
		//Thread.sleep(3000);
	}
	
	@Test
	public void testPutTicket() throws WWPassProtocolException, UnsupportedEncodingException, IOException, InterruptedException {
		
		try {
			
			// Invalid ticket case
			try {
				conn.putTicket(tickets.get(1));
				fail("Expected an WWPassProtocolException with message \"Invalid or timed out ticket\"");
			} catch (WWPassProtocolException e) {
				assertTrue("Expected message: \"Invalid or timed out ticket\", actual message: " + e.getMessage(), 
						e.getMessage().contains("Invalid or timed out ticket"));
			} 

            // Normal usage case
            try {
                conn.putTicket(tickets.get(0));
            } catch (WWPassProtocolException e) {
                fail("Expected no exception, but catched: " + e.getMessage());
            }

			// Custom TTL case
			String[] userTicket = testUtils.getTicket().split(" ", 2);
			if ("200".equals(userTicket[0])) {
				String ticketTTL = conn.putTicket(userTicket[1], 3);
				Thread.sleep(5000);
				try {
					conn.getPUID(ticketTTL);
					fail("Expected an WWPassProtocolException with message \"Nonexistent or timed out ticket\"");
				} catch (WWPassProtocolException e) {
					assertTrue("Expected message: \"Nonexistent or timed out ticket\", actual message: " + e.getMessage(), 
							e.getMessage().contains("Nonexistent or timed out ticket") 
							|| e.getMessage().contains("Invalid ticket"));
				}
			} else {
				throw new IllegalArgumentException("Error occured while getting user ticket. Error code: "
						+ userTicket[0] + ". Message: " + userTicket[1]);
			}
			
			// Custom TTL and "p" auth_type case
			userTicket = testUtils.getTicketWithP().split(" ", 2);
			if ("200".equals(userTicket[0])) {
				String ticketTTL = conn.putTicket(userTicket[1], "p", 3);
				Thread.sleep(5000);
				try {
					conn.getPUID(ticketTTL);
					fail("Expected an WWPassProtocolException with message \"Nonexistent or timed out ticket\"");
				} catch (WWPassProtocolException e) {
					assertTrue("Expected message: \"Nonexistent or timed out ticket\", actual message: " + e.getMessage(), 
							e.getMessage().contains("Nonexistent or timed out ticket") 
							|| e.getMessage().contains("Invalid ticket"));
				}
			} else {
				throw new IllegalArgumentException("Error occured while getting user ticket. Error code: "
						+ userTicket[0] + ". Message: " + userTicket[1]);
			}	
			
			// "p" auth_type case
			userTicket = testUtils.getTicketWithP().split(" ", 2);
			if ("200".equals(userTicket[0])) {
				String ticketP = conn.putTicket(userTicket[1], "p");
				try {
					conn.getPUID(ticketP);
				} catch (WWPassProtocolException e) {
					fail("Expected no exception, but catched: " + e.getMessage());
				}
			} else {
				throw new IllegalArgumentException("Error occured while getting user ticket. Error code: "
						+ userTicket[0] + ". Message: " + userTicket[1]);
			}	
			
			
		} catch (WWPassProtocolException e) {
			fail("Expected no exception while putting valid ticket, but catched: " + e.getMessage());
		}
		
	}
	@Test
	public void testGetPuid() throws UnsupportedEncodingException, IOException, WWPassProtocolException, InterruptedException {

		// Normal behavior
		String puid = conn.getPUID(tickets.get(0));
		assertArrayEquals("PUID is not as expected",
					"4006fb737838a514d7fcacae94f8968b".getBytes(),
					puid.getBytes());

		// Invalid ticket
		try {
			puid = conn.getPUID(tickets.get(1));
			fail("Expected an WWPassProtocolException with message \"Invalid or timed out ticket\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Invalid or timed out ticket\", actual message: " + e.getMessage(), 
					e.getMessage().contains("Invalid or timed out ticket"));
		} 
		
		// Invalid ticket format
		try {
			puid = conn.getPUID(tickets.get(2));
			fail("Expected an WWPassProtocolException with message \"Invalid ticket format\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Invalid ticket format\", actual message: " + e.getMessage(), 
					e.getMessage().contains("Invalid ticket format"));
		} 
		
		// Empty ticket
		try {
			puid = conn.getPUID(tickets.get(3));
			fail("Expected an WWPassProtocolException with message \"Invalid ticket format\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Invalid ticket format\", actual message: " + e.getMessage(), 
					e.getMessage().contains("Invalid ticket format"));
		} 
		
		// *************************** //
		//   Testing "p" auth_type     //
		// *************************** //
		
		// Normal behavior
		String[] ticketP = testUtils.getTicketWithP().split(" ", 2);
		if ("200".equals(ticketP[0])) {
			puid = conn.getPUID(ticketP[1], "p");
			assertArrayEquals("PUID is not as expected",
					"4006fb737838a514d7fcacae94f8968b".getBytes(), puid.getBytes());
		} else {
			throw new IllegalArgumentException(
					"Error occured while getting user ticket. Error code: "
							+ ticketP[0] + ". Message: " + ticketP[1]);
		}
		
		// Ticket was authorized with less factors than requested
		try {
			conn.getPUID(tickets.get(0), "p");
			fail("Expected an WWPassProtocolException with message \"Ticket was authorized with less factors than requested\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Ticket was authorized with less factors than requested\", actual message: "	+ e.getMessage(),
						e.getMessage().contains("Ticket was authorized with less factors than requested"));
		}
	}

	@Test
	public void testReadDataAsString() throws WWPassProtocolException, UnsupportedEncodingException, IOException {

		// Read data from empty container case
		String data = conn.readDataAsString(tickets.get(0));
		assertArrayEquals("Expected an empty string, but returned: " + data.getBytes(),
							"".getBytes(), 
							data.getBytes());
		
		conn.writeData(tickets.get(0), BYTE_DATA);
		data = conn.readDataAsString(tickets.get(0));
		assertNotEquals("Expected that returned data not equals to written", BYTE_DATA, data.getBytes());
		
		conn.writeData(tickets.get(0), "test data", "string");
		data = conn.readDataAsString(tickets.get(0), "string");
		assertArrayEquals("Expected that written and readed data are equal", "test data".toCharArray(), data.toCharArray());

	}
	
	@Test
	public void testReadWriteData() throws UnsupportedEncodingException,
			IOException, WWPassProtocolException, DecoderException {
		
		InputStream dataIs;
		BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		// Invalid ticket read case
		try {
			conn.readData(tickets.get(1));
			fail("Expected an WWPassProtocolException with message \"Invalid ticket URL\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Invalid ticket URL\", actual message: " + e.getMessage(), 
					e.getMessage().contains("Invalid ticket URL"));
		} 
		
		// Invalid ticket format read case
		try {
			conn.readData(tickets.get(2));
			fail("Expected an WWPassProtocolException with message \"Invalid ticket format\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Invalid ticket format\", actual message: " + e.getMessage(), 
					e.getMessage().contains("Invalid ticket format"));
		} 
		// Invalid ticket write case
		try {
			conn.writeData(tickets.get(1), "invalid ticket case");
			fail("Expected an WWPassProtocolException with message \"Invalid ticket URL\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Invalid ticket URL\", actual message: " + e.getMessage(), 
						e.getMessage().contains("Invalid ticket URL"));
		} 
		// Write and read string data case
		conn.writeData(tickets.get(0), "test data");
		dataIs = conn.readData(tickets.get(0));
        
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Expected an empty string", "test data".getBytes(), baos.toByteArray());
        } finally {
        	bis.close();
        	baos.reset();
        	baos.close();
        }
		

		// Write and read byte data (small size)
		conn.writeData(tickets.get(0), BYTE_DATA, "testbyte");
		dataIs = conn.readData(tickets.get(0), "testbyte");
        
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Expected an non string data", BYTE_DATA, baos.toByteArray());
        } finally {
        	bis.close();
        	baos.reset();
        	baos.close();
        }
		
		// Write and read byte data (large size)
	    conn.writeData(tickets.get(0), imgData);
	    dataIs = conn.readData(tickets.get(0));
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Expected an image represented as bytes array data", imgData,	baos.toByteArray());
        } finally {
        	bis.close();
        	baos.reset();
        	baos.close();
        }
	    
		// Valid ticket/container doesn't exist case
		dataIs = conn.readData(tickets.get(0), "doesn't exist");
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Expected \"None\", but returned: " + new String(baos.toByteArray()),
					"None".getBytes(),	baos.toByteArray());
        } finally {
        	bis.close();
        	baos.reset();
        	baos.close();
        }

		// Valid container/valid ticket case
		conn.writeData(tickets.get(0), "test data", "test");
		dataIs = conn.readData(tickets.get(0), "test");
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Expected \"test data\", but returned: " + new String(baos.toByteArray()),
		    		"test data".getBytes(),	baos.toByteArray());
        } finally {
        	bis.close();
        	baos.reset();
        	baos.close();
        }

		// Invalid container/valid ticket case
		try {
			conn.readData(tickets.get(0), "0123456789ABCDEFG");
			fail("Expected an WWPassProtocolException with message \"Container ID too long\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Container ID too long\", actual message: " + e.getMessage(),
						e.getMessage().contains("Container ID too long"));
		}
		
		// Valid ticket/invalid container case
		try {
			conn.writeData(tickets.get(0), "test data", "0123456789ABCDEFG");
			fail("Expected an WWPassProtocolException with message \"Container ID too long\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Container ID too long\", actual message: "	+ e.getMessage(),
						e.getMessage().contains("Container ID too long"));
		}	
		
		
	}
	
	@Test
	public void testLockAndUnlock() throws UnsupportedEncodingException,
			IOException, WWPassProtocolException, InterruptedException {
		
		// Invalid ticket read case
		try {
			conn.lock(tickets.get(1), 1);
			fail("Expected an WWPassProtocolException with message \"Invalid or timed out ticket\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Invalid or timed out ticket\", actual message: " + e.getMessage(), 
					e.getMessage().contains("Invalid ticket URL"));
		} 
		
		// lockTimeout == 0 case
		try {
			conn.lock(tickets.get(0), 0);
		} catch (WWPassProtocolException e) {
			assertFalse("Expecting no exception, but catched the WWPassProtocolException with message: " + e.getMessage(), 
						e.getMessage().contains("Already locked"));
		}
		
		// Getting "Already locked" error
		try {
			conn.lock(tickets.get(0), 10);
			conn.lock(tickets.get(0), 10);
			fail("Expected an WWPassProtocolException with message \"Already locked\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
					e.getMessage().contains("Already locked"));
		}
		
		// Getting "Not locked" error
		conn.unlock(tickets.get(0));
		try {
			conn.unlock(tickets.get(0));
			fail("Expected an WWPassProtocolException with message \"Not locked\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
					e.getMessage().contains("Not locked"));
		}
		
		// Checking that lock is released after timeout
		try {
			conn.lock(tickets.get(0), 5);
			Thread.sleep(5000);
			conn.lock(tickets.get(0), 1);
		} catch (WWPassProtocolException e) {
			assertFalse("Expecting no exception, but catched the WWPassProtocolException with message \"Already locked\".", 
						e.getMessage().contains("Already locked"));
		}
		
		try {
			conn.lock(tickets.get(0), 1, "test_lock");
			conn.unlock(tickets.get(0), "test_lock");
		} catch (WWPassProtocolException e) {
			fail("Expected no exception, but catched: " + e.getMessage());
		}
	}
	
	@Test
	public void testGetName() throws UnsupportedEncodingException,
			IOException, WWPassProtocolException {
		
		String name = conn.getName();
		assertArrayEquals("Excpected name \"SDK%20Test\", but actual value is \"" + name + "\".", 
							"SDK%20Test".getBytes(), 
							name.getBytes());
	}
	
	@Test
	public void testWriteReadLockUnlock() 
			throws WWPassProtocolException, UnsupportedEncodingException, 
					IOException, InterruptedException {
		conn.writeData(tickets.get(0), "");
		
		
		conn.readDataAndLock(tickets.get(0), 2);
		try {
			conn.lock(tickets.get(0), 1);
			fail("Expected WWPassProtocolException with message \"Already locked\"");
		} catch(WWPassProtocolException e) {
			assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
					e.getMessage().contains("Already locked"));
		}		
		Thread.sleep(2000);
		
		conn.lock(tickets.get(0), 2);
		try {
			conn.writeDataAndUnlock(tickets.get(0), BYTE_DATA);
		} catch (WWPassProtocolException e) {
			fail("Expected no exception, but catched: " + e.getMessage());
		}
		try {
			conn.unlock(tickets.get(0));
			fail("Expected an WWPassProtocolException with message \"Not locked\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
					e.getMessage().contains("Not locked"));
		}
		
		conn.writeData(tickets.get(0), "test data", "lock_string");
		conn.readDataAndLock(tickets.get(0), "lock_string", 2);
		try {
			conn.writeDataAndUnlock(tickets.get(0), BYTE_DATA, "lock_string");
		} catch (WWPassProtocolException e) {
			fail("Expected no exception, but catched: " + e.getMessage());
		}
		try {
			conn.unlock(tickets.get(0));
			fail("Expected an WWPassProtocolException with message \"Not locked\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
					e.getMessage().contains("Not locked"));
		}
	}
	
	// Functions to work with SP-only containers
	
	@Test 
	public void testCreatePFID() throws UnsupportedEncodingException,
			IOException, WWPassProtocolException {
		byte[] pfid1 = conn.createPFID();
		byte[] pfid2 = conn.createPFID("test data");
		
		//String data1 = conn.readDataSP(pfid1);
		//assertArrayEquals("Expected an empty string, but recieved: " + data1, "".getBytes(), data1.getBytes());
		InputStream dataIs = conn.readDataSP(pfid1);
		BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Expected an empty string, but recieved: " + new String(baos.toByteArray()), 
		    					"".getBytes(), baos.toByteArray());
        } finally {
        	bis.close();
        	baos.close();
        }
		
		//String data2  = conn.readDataSP(pfid2);
		//assertArrayEquals("Excpected \"test data\", but recieved: " + data2, "test data".getBytes(), data2.getBytes());
		dataIs = conn.readDataSP(pfid2);
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Excpected \"test data\", but recieved: " + new String(baos.toByteArray()), 
		    					"test data".getBytes(), baos.toByteArray());
        } finally {
        	bis.close();
        	baos.close();
        }
        
        conn.readDataSPandLock(pfid2, 5);
        try {
            conn.lockSP(pfid2, 5);
            fail("Ecpected WWPassProtocolException with message \"Already locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Already locked"));
        }
        conn.writeDataSPandUnlock(pfid2, "test data two");
        try {
            conn.unlockSP(pfid2);
            fail("Expected WWPassProtocolException with message \"Not locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Not locked"));
        }
        
		try {
			conn.removePFID(pfid1);
			conn.removePFID(pfid2);
		} catch (WWPassProtocolException e) {
			fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
		}
	}

	@Test
	public void testRemovePFID() throws UnsupportedEncodingException, IOException {
		
		// Invalid PFID case
		try {
			conn.removePFID(BYTE_DATA);
			fail("Expected WWPassProtocolException with message \"Invalid or absent PFID\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message \"Invalid or absent PFID\", actual message: " + e.getMessage(), 
						e.getMessage().contains("Invalid or absent PFID"));
		}
		
		// Normal usage case
		byte[] pfid = conn.createPFID();
		try {
			conn.removePFID(pfid);
		} catch (WWPassProtocolException e) {
			fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
		}
		try {
			conn.removePFID(pfid);
			fail("Expected WWPassProtocolException with message \"ID does not exist\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message \"ID does not exist\", actual message: " + e.getMessage(), 
						e.getMessage().contains("ID does not exist"));
		}
	}
	
	@Test
	public void testWriteDataSP() throws WWPassProtocolException, UnsupportedEncodingException, IOException {
		byte[] pfid = conn.createPFID();
		
		// Write and read string data case
		conn.writeDataSP(pfid, "test data");
		/*String response = conn.readDataSP(pfid);
		assertArrayEquals("Expected readed data \"test data\", actual readed data is " + response, 
							"test data".getBytes(), 
							response.getBytes());*/
		InputStream dataIs = conn.readDataSP(pfid);
		BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Expected readed data \"test data\", actual readed data is " + new String(baos.toByteArray()), 
		    					"test data".getBytes(), 
		    					baos.toByteArray());
        } finally {
        	bis.close();
        	baos.reset();
        	baos.close();
        }
		try {
			conn.removePFID(pfid);
		} catch (WWPassProtocolException e) {
			fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
		}
		
		// Write and read byte data case
		pfid = conn.createPFID();
		conn.writeDataSP(pfid, BYTE_DATA);
/*		byte[] byteResponse = conn.readDataBytesSP(pfid);
		assertArrayEquals("Writed and readed byte data are not equals", BYTE_DATA, byteResponse);*/
		dataIs = conn.readDataSP(pfid);
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Writed and readed byte data are not equals. Returned data: " + new String(baos.toByteArray()), 
		    					BYTE_DATA, 
		    					baos.toByteArray());
        } finally {
        	bis.close();
        	baos.reset();
        	baos.close();
        }
		try {
			conn.removePFID(pfid);
		} catch (WWPassProtocolException e) {
			fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
		}
		
		// Write and read large byte data (JPG image) case
		pfid = conn.createPFID();
		conn.writeDataSP(pfid, imgData);
/*		byte[] newImgData = conn.readDataBytesSP(pfid);
		assertArrayEquals("Writed and readed byte data are not equals", imgData, newImgData);*/
		dataIs = conn.readDataSP(pfid);
        try {
	        bis = new BufferedInputStream(dataIs);
	
	        byte[] buffer = new byte[8192];
		    int bytesRead;
		    
		    while ((bytesRead = bis.read(buffer)) != -1)
		    {
		    	baos.write(buffer, 0, bytesRead);
		    }
		    assertArrayEquals("Writed and readed byte data are not equals", imgData, baos.toByteArray());
        } finally {
        	bis.close();
        	baos.reset();
        	baos.close();
        }
		try {
			conn.removePFID(pfid);
		} catch (WWPassProtocolException e) {
			fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
		}

        // Write and read String data case
        pfid = conn.createPFID("test data");
        String stringData = conn.readDataSPasString(pfid);
        assertArrayEquals("Expected that readed and writed string data are equal", "test data".getBytes(), stringData.getBytes());

        // Test for read String and lock SP
        conn.readDataSPasStringAndLock(pfid, 3);
        try{
            conn.lockSP(pfid, 1);
            fail("Expected WWPassProtocolException while trying to lock already locked SP container");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Already locked"));
        }
        try {
            conn.removePFID(pfid);
        } catch (WWPassProtocolException e) {
            fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
        }



	}
	
	@Test
	public void testLockAndUnlockSP() throws UnsupportedEncodingException,
			IOException, WWPassProtocolException, InterruptedException {
		
		// Custom lock timeout case
		byte[] pfid = conn.createPFID();
		try {
			conn.lockSP(pfid, 10);
			conn.lockSP(pfid, 10);
			fail("Expected an WWPassProtocolException with message \"Already locked\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
					e.getMessage().contains("Already locked"));
		}
		
		// Trying unlock doesn't lock container
		conn.unlockSP(pfid);
		try {
			conn.unlockSP(pfid);
			fail("Expected an WWPassProtocolException with message \"Not locked\"");
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
					e.getMessage().contains("Not locked"));
		}
		
		// Checking that timeout expires
		try {
			conn.lockSP(pfid, 5);
			Thread.sleep(5000);
			conn.unlockSP(pfid);
		} catch (WWPassProtocolException e) {
			assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
					e.getMessage().contains("Not locked"));
		}
		
		// Removing test data
		try {
			conn.removePFID(pfid);
		} catch (WWPassProtocolException e) {
			fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
		}
	}
}
