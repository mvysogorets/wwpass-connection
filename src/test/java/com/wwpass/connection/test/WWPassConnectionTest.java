package com.wwpass.connection.test;

import com.wwpass.connection.WWPassConnection;
import com.wwpass.connection.exceptions.WWPassProtocolException;
import com.wwpass.connection.util.TestUtils;
import org.junit.*;

import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import com.google.code.tempusfugit.concurrency.ConcurrentTestRunner;

import java.io.*;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * WWPassConnection Tester. 
 *
 * @author Stanislav Panyushkin <s.panyushkin@wwpass.com
 * @since <pre>Nov 1, 2013</pre> 
 * @version 1.0
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

    /**
     *
     * Method: getPUID(String ticket, String auth_type) 
     *
     */
    @Test
    public void testGetPUIDForTicketAuth_type() throws Exception {
        String puid;
        
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

    /**
     *
     * Method: getPUID(String ticket) 
     *
     */
    @Test
    public void testGetPUIDTicket() throws Exception {
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
    }

    /**
     *
     * Method: getTicket(String auth_type, int ttl) 
     *
     */
    @Test
    public void testGetTicketForAuth_typeTtl() throws Exception {
        String ticket = conn.getTicket();
        
        // Custom TTL and "p" auth_type case
        ticket =conn.getTicket("p", 3);
        Thread.sleep(3000);
        String[] newTicket = testUtils.authenticateTicketWithP(ticket).split(" ", 2);
        assertTrue("Expected error code 400, but returned: " + newTicket[0],
                "400".equals(newTicket[0]));
    }

    /**
     *
     * Method: getTicket(String auth_type) 
     *
     */
    @Test
    public void testGetTicketAuth_type() throws Exception {
        // "p" auth_type case
        String ticket = conn.getTicket("p");
        String[] newTicket;
        
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
    }

    /**
     *
     * Method: getTicket(int ttl) 
     *
     */
    @Test
    public void testGetTicketTtl() throws Exception {
        // Custom TTL case
        String ticket = conn.getTicket(3);
        Thread.sleep(5000);
        String[] newTicket = testUtils.authenticateTicket(ticket).split(" ", 2);
        assertTrue("Expected error code 400, but returned: " + newTicket[0],
                "400".equals(newTicket[0]));
    }

    /**
     *
     * Method: getTicket() 
     *
     */
    @Test
    public void testGetTicket() throws Exception {
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
    }

    /**
     *
     * Method: getName() 
     *
     */
    @Test
    public void testGetName() throws Exception {
        String name = conn.getName();
        assertArrayEquals("Excpected name \"SDK%20Test\", but actual value is \"" + name + "\".",
                "SDK%20Test".getBytes(),
                name.getBytes());
    }

    /**
     *
     * Method: putTicket(String ticket, String auth_type, int ttl) 
     *
     */
    @Test
    public void testPutTicketForTicketAuth_typeTtl() throws Exception {
        // Custom TTL and "p" auth_type case
        String[] userTicket = testUtils.getTicketWithP().split(" ", 2);
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
    }

    /**
     *
     * Method: putTicket(String ticket, String auth_type) 
     *
     */
    @Test
    public void testPutTicketForTicketAuth_type() throws Exception {
        // "p" auth_type case
        String[] userTicket = testUtils.getTicketWithP().split(" ", 2);
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
    }

    /**
     *
     * Method: putTicket(String ticket, int ttl) 
     *
     */
    @Test
    public void testPutTicketForTicketTtl() throws Exception {
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
    }

    /**
     *
     * Method: putTicket(String ticket) 
     *
     */
    @Test
    public void testPutTicketTicket() throws Exception {
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
    }

    /**
     *
     * Method: readData(String ticket, String container) 
     *
     */
    @Test
    public void testReadDataForTicketContainer() throws Exception {
        InputStream dataIs;
        BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
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
            if (bis != null) {
                bis.close();
            }
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

    /**
     *
     * Method: readDataAsString(String ticket, String container) 
     *
     */
    @Test
    public void testReadDataAsStringForTicketContainer() throws Exception {
        conn.writeData(tickets.get(0), "test data", "string");
        String data = conn.readDataAsString(tickets.get(0), "string");
        assertArrayEquals("Expected that written and readed data are equal", "test data".toCharArray(), data.toCharArray());
    }

    /**
     *
     * Method: readData(String ticket) 
     *
     */
    @Test
    public void testReadDataTicket() throws Exception {
        

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
        
    }

    /**
     *
     * Method: readDataAsString(String ticket) 
     *
     */
    @Test
    public void testReadDataAsStringTicket() throws Exception {
        // Read data from empty container case
        String data = conn.readDataAsString(tickets.get(0));
        assertArrayEquals("Expected an empty string, but returned: " + data.getBytes(),
                "".getBytes(),
                data.getBytes());

        conn.writeData(tickets.get(0), BYTE_DATA);
        data = conn.readDataAsString(tickets.get(0));
        assertNotEquals("Expected that returned data not equals to written", BYTE_DATA, data.getBytes());
    }

    /**
     *
     * Method: readDataAndLock(String ticket, String container, int lockTimeout) 
     *
     */
    @Test
    public void testReadDataAndLockForTicketContainerLockTimeout() throws Exception {
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

    /**
     *
     * Method: readDataAsStringAndLock(String ticket, String container, int lockTimeout) 
     *
     */
    @Test
    public void testReadDataAsStringAndLockForTicketContainerLockTimeout() throws Exception {
        conn.writeData(tickets.get(0),"string data", "string");
        String data = conn.readDataAsStringAndLock(tickets.get(0), "string", 5);
        
        assertArrayEquals("Expected the same string data that was writed", "string data".getBytes(), data.getBytes());
        
        try {
            conn.lock(tickets.get(0), 1, "string");
            fail("Expected WWPassProtocolException with message \"Already locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Already locked"));
        }
        
        try {
            conn.writeDataAndUnlock(tickets.get(0), "", "string");
        } catch (WWPassProtocolException e) {
            fail("Expected no WWPassProtocolException, but catched with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: readDataAndLock(String ticket, int lockTimeout) 
     *
     */
    @Test
    public void testReadDataAndLockForTicketLockTimeout() throws Exception {
        conn.writeData(tickets.get(0), "");

        conn.readDataAndLock(tickets.get(0), 2);
        try {
            conn.lock(tickets.get(0), 1);
            fail("Expected WWPassProtocolException with message \"Already locked\"");
        } catch(WWPassProtocolException e) {
            assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Already locked"));
        }
    }

    /**
     *
     * Method: readDataAsStringAndLock(String ticket, int lockTimeout) 
     *
     */
    @Test
    public void testReadDataAsStringAndLockForTicketLockTimeout() throws Exception {
        conn.writeData(tickets.get(0),"string data");
        
        String data = conn.readDataAsStringAndLock(tickets.get(0), 5);

        assertArrayEquals("Expected the same string data that was writed", "string data".getBytes(), data.getBytes());

        try {
            conn.lock(tickets.get(0), 1);
            fail("Expected WWPassProtocolException with message \"Already locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Already locked"));
        }

        try {
            conn.writeDataAndUnlock(tickets.get(0), "");
        } catch (WWPassProtocolException e) {
            fail("Expected no WWPassProtocolException, but catched with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: writeData(String ticket, String data, String container) 
     *
     */
    @Test
    public void testWriteDataForTicketDataContainer() throws Exception {
        InputStream dataIs;
        BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
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
            if (bis != null) {
                bis.close();
            }
            baos.reset();
            baos.close();
        }
    }

    /**
     *
     * Method: writeData(String ticket, String data) 
     *
     */
    @Test
    public void testWriteDataForTicketData() throws Exception {
        InputStream dataIs;
        BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
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
            if (bis != null) {
                bis.close();
            }
            baos.reset();
            baos.close();
        }
    }

    /**
     *
     * Method: writeDataAndUnlock(String ticket, String data, String container) 
     *
     */
    @Test
    public void testWriteDataAndUnlockForTicketDataContainer() throws Exception {
        // Not locked case
        try {
            conn.writeDataAndUnlock(tickets.get(0), "string data", "string");
            fail("Expected WWPassProtocolException with message \"Not locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Not locked"));
        }
        
        // write to locked container case
        conn.lock(tickets.get(0), 5, "string");
        try {
            conn.writeDataAndUnlock(tickets.get(0), "string data", "string");
        } catch (WWPassProtocolException e) {
            fail("Expected no WWPassProtocolException, but catched with message: " + e.getMessage());
        }
        
        // checking that lock was released
        try {
            conn.unlock(tickets.get(0), "string");
            fail("Expected WWPassProtocolException with message \"Not locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Not locked"));
        }
        
    }

    /**
     *
     * Method: writeDataAndUnlock(String ticket, String data) 
     *
     */
    @Test
    public void testWriteDataAndUnlockForTicketData() throws Exception {
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
    }

    /**
     *
     * Method: lock(String ticket, int lockTimeout, String lockid) 
     *
     */
    @Test
    public void testLockForTicketLockTimeoutLockid() throws Exception {
        // normal behavior case
        try {
            conn.lock(tickets.get(0), 1, "test_lock");
            conn.unlock(tickets.get(0), "test_lock");
        } catch (WWPassProtocolException e) {
            fail("Expected no exception, but catched: " + e.getMessage());
        }
        
        // getting "Already locked" exception
        conn.lock(tickets.get(0), 5, "test_lock");
        try {
            conn.lock(tickets.get(0), 5, "test_lock");
            fail("Expected WWPassProtocolException with message \"Already locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Already locked"));
        }
    }

    /**
     *
     * Method: lock(String ticket, int lockTimeout) 
     *
     */
    @Test
    public void testLockForTicketLockTimeout() throws Exception {
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
        conn.unlock(tickets.get(0));

        // Checking that lock is released after timeout
        try {
            conn.lock(tickets.get(0), 3);
            Thread.sleep(4000);
            conn.lock(tickets.get(0), 1);
        } catch (WWPassProtocolException e) {
            fail("Expecting no exception, but catched the WWPassProtocolException with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: unlock(String ticket, String lockid) 
     *
     */
    @Test
    public void testUnlockForTicketLockid() throws Exception {
        
        // Getting "Not locked" error
        try {
            conn.unlock(tickets.get(0), "test_unlock");
            fail("Expected an WWPassProtocolException with message \"Not locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Not locked"));
        }
        
        // Normal behavior
        try {
            conn.lock(tickets.get(0), 1, "test_unlock");
            conn.unlock(tickets.get(0), "test_unlock");
        } catch (WWPassProtocolException e) {
            fail("Expected no exception, but catched: " + e.getMessage());
        }
        
        // Invalid lockid case
        try {
            conn.unlock(tickets.get(0), "0123456789abcdefgh");
            fail("Expected WWPassProtocolException");
        } catch (WWPassProtocolException e) {
            
        }
    }

    /**
     *
     * Method: unlock(String ticket) 
     *
     */
    @Test
    public void testUnlockTicket() throws Exception {
        
        // Getting "Not locked" error
        try {
            conn.unlock(tickets.get(0));
            fail("Expected an WWPassProtocolException with message \"Not locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Not locked"));
        }

        // Normal behavior 
        try {
            conn.lock(tickets.get(0), 1);
            conn.unlock(tickets.get(0));
        } catch (WWPassProtocolException e) {
            fail("Expected no exception, but catched: " + e.getMessage());
        }
    }

    /**
     *
     * Method: createPFID(String data) 
     *
     */
    @Test
    public void testCreatePFIDData() throws Exception {
        InputStream dataIs;
        BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        byte[] pfid2 = conn.createPFID("test data");

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
            conn.removePFID(pfid2);
        } catch (WWPassProtocolException e) {
            fail("Expecting no exception while removing test PFID, but catched the WWPassProtocolException with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: createPFID() 
     *
     */
    @Test
    public void testCreatePFID() throws Exception {
        byte[] pfid1 = conn.createPFID();

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

        try {
            conn.removePFID(pfid1);
        } catch (WWPassProtocolException e) {
            fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: removePFID(byte[] pfid) 
     *
     */
    @Test
    public void testRemovePFID() throws Exception {
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

    /**
     *
     * Method: readDataSP(byte[] pfid) 
     *
     */
    @Test
    public void testReadDataSP() throws Exception {
        byte[] pfid;
        InputStream dataIs;
        BufferedInputStream bis = null;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        
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
    }

    /**
     *
     * Method: readDataSPasString(byte[] pfid) 
     *
     */
    @Test
    public void testReadDataSPasString() throws Exception {
        byte[] pfid;

        // Write and read String data case
        pfid = conn.createPFID("test data");
        String stringData = conn.readDataSPasString(pfid);
        assertArrayEquals("Expected that readed and writed string data are equal", "test data".getBytes(), stringData.getBytes());

        try {
            conn.removePFID(pfid);
        } catch (WWPassProtocolException e) {
            fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: readDataSPandLock(byte[] pfid, int lockTimeout) 
     *
     */
    @Test
    public void testReadDataSPandLock() throws Exception {
        byte[] pfid = conn.createPFID();
        
        // Getting "Already locked" exception
        conn.readDataSPandLock(pfid, 5);
        try {
            conn.lockSP(pfid, 1);
            fail("Ecpected WWPassProtocolException with message \"Already locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Already locked"));
        }
        conn.unlockSP(pfid);
        
        // Checking that lock is releases
        conn.lockSP(pfid, 3);
        Thread.sleep(4000);
        try {
            conn.lockSP(pfid, 1);
        } catch (WWPassProtocolException e) {
            fail("Expected no exception, but catched: " + e.getMessage());
        }

        // Removing test data
        try {
            conn.removePFID(pfid);
        } catch (WWPassProtocolException e) {
            fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: readDataSPasStringAndLock(byte[] pfid, int lockTimeout) 
     *
     */
    @Test
    public void testReadDataSPasStringAndLock() throws Exception {
        byte[] pfid = conn.createPFID();
        
        // Getting "Already locked" exception
        conn.lockSP(pfid, 5);
        try {
            conn.readDataSPasStringAndLock(pfid, 1);
            fail("Ecpected WWPassProtocolException with message \"Already locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Already locked"));
        }

        // Removing test data
        try {
            conn.removePFID(pfid);
        } catch (WWPassProtocolException e) {
            fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: writeDataSP(byte[] pfid, String data) 
     *
     */
    @Test
    public void testWriteDataSPForPfidData() throws Exception {
        byte[] pfid = conn.createPFID();

        // Write and read string data case
        conn.writeDataSP(pfid, "test data");
		String response = conn.readDataSPasString(pfid);
		assertArrayEquals("Expected readed data \"test data\", actual readed data is " + response, 
							"test data".getBytes(), 
							response.getBytes());

        // Removing test data
        try {
            conn.removePFID(pfid);
        } catch (WWPassProtocolException e) {
            fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: writeDataSPandUnlock(byte[] pfid, String data) 
     *
     */
    @Test
    public void testWriteDataSPandUnlockForPfidData() throws Exception {
        byte[] pfid = conn.createPFID();
        
        // Getting "Not locked" exception
        try {
            conn.writeDataSPandUnlock(pfid, "data");
            fail("Expected WWPassProtocolException with message \"Not locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Not locked"));
        }
        
        // Normal lock release
        conn.lockSP(pfid, 5);
        try {
            conn.writeDataSPandUnlock(pfid, "data");
        } catch (WWPassProtocolException e) {
            fail("Expected no WWPassProtocolException, but catched with message: " + e.getMessage());
        }

        // Removing test data
        try {
            conn.removePFID(pfid);
        } catch (WWPassProtocolException e) {
            fail("Expecting no exception while removing test PFIDs, but catched the WWPassProtocolException with message: " + e.getMessage());
        }
    }

    /**
     *
     * Method: lockSP(byte[] lockid, int lockTimeout) 
     *
     */
    @Test
    public void testLockSP() throws Exception {
        byte[] pfid = conn.createPFID();
        
        // Custom lock timeout case
        try {
            conn.lockSP(pfid, 10);
            conn.lockSP(pfid, 10);
            fail("Expected an WWPassProtocolException with message \"Already locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Already locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Already locked"));
        }
        conn.unlockSP(pfid);

        // Checking that timeout expires
        try {
            conn.lockSP(pfid, 3);
            Thread.sleep(4000);
            conn.unlockSP(pfid);
            fail("Expected an WWPassProtocolException with message \"Not locked\"");
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

    /**
     *
     * Method: unlockSP(byte[] lockid) 
     *
     */
    @Test
    public void testUnlockSP() throws Exception {
        byte[] pfid = conn.createPFID();
        
        // Trying unlock doesn't lock container
        try {
            conn.unlockSP(pfid);
            fail("Expected an WWPassProtocolException with message \"Not locked\"");
        } catch (WWPassProtocolException e) {
            assertTrue("Expected message: \"Not locked\", actual message: "	+ e.getMessage(),
                    e.getMessage().contains("Not locked"));
        }
    }



} 
