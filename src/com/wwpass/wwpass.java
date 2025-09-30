package com.wwpass;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Servlet implementation class wwpass
 */
@SuppressWarnings("unused")
@WebServlet("/wwpass")
public class wwpass extends HttpServlet {
    private static final long serialVersionUID = 1L;

    //----------Declare and initialize SP_name, certfile, keyfile, puid, ticket and newTicket-------------------------------------------------------------------------------
    final String SP_name = "SDK%20Test";
    final String certfile = "C:/sdk-test/SDK_Test.crt";
    final String keyfile = "C:/sdk-test/SDK_Test.key";
    final String cafile = "C:/sdk-test/wwpass_sp_ca.crt";

    String puid = null;
    String ticket = null;
    String newTicket = null;

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @see HttpServlet#HttpServlet()
     */
    public wwpass() {
        super();
        // TODO Auto-generated constructor stub
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
     */

    @SuppressWarnings("RedundantThrows")
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

//-------------------------Start session----------------------------------------------------------------------------
        HttpSession session = request.getSession(true);
        if (null == session.getAttribute("puid")) {
            // User is not logged in yet
            if (request.getParameter("ticket") == null) { // If there's no ticket in GET request
/* ----------------------------------------------------------------------------------------------------------------------
                Step 1: No ticket, so show a screen with a login button. The button click starts token authentication.
                On success token obtains a ticket for our Service Provider.
                The ticket will be sent to web server in a GET request
------------------------------------------------------------------------------------------------------------------------------*/
                request.setAttribute("SP_name", SP_name); // Put SP_name into GET request
                RequestDispatcher RequestDispatcherObj = request.getRequestDispatcher("/wwpass.jsp");
                RequestDispatcherObj.forward(request, response); // Load the JSP
            } else {
/*--------------------------- Step 2: ----------------------------------------------------------------------------------------------
                We got a ticket in GET request
                Our app will authenticate itself in WWPass and send the ticket
                On success the application will be allowed to obtain this user PUID
--------------------------------------------------------------------------------------------------------------------------------------*/
                ticket = request.getParameter("ticket");              // GET ticket and store in String
                WWPassConnection cls;                                       // Load WWPass library
                try {
                    cls = new WWPassConnection(SP_name, SP_name, SP_name);  // Authenticate in WWPass
                    newTicket = cls.putTicket(ticket);                      // Get new ticket from putTicket;
                    puid = cls.getPUID(newTicket);                          // Get the PUID
                    session.setAttribute("puid", puid);               // Set PUID to the current session
                    tester();                                               // Test read/write functions
                    RequestDispatcher RequestDispatcherObj = request.getRequestDispatcher("/wwpass");
                    RequestDispatcherObj.forward(request, response);        // Refresh the current servlet while retaining the session
                } catch (Exception e) {
                    //noinspection CallToPrintStackTrace
                    e.printStackTrace();
                }
            }   //End of ticket Else
        }       //End of null PUID
        else {
/*---------------------------- Step 3:-------------------------------------------------------------------------------------
            Puid exists in the session: user already authenticated,
            Routine work with the local database can be done, no more WWPass specifics

            In more advanced cases, we might use WWPass data containers to keep some - or all - user data.
            This functionality exceeds that of basic PUID service.
            See SP SDK for details.
---------------------------------------------------------------------------------------------------------------------------------*/
            System.out.println("Logged in!"); // Show the generic "Logged in!" message
            System.out.println("PUID: " + session.getAttribute("puid"));
            System.out.println("Ticket: " + request.getParameter("ticket"));
            if (request.getParameter("logout") != null) { // Logout function
                session.removeAttribute("puid");
                RequestDispatcher RequestDispatcherObject = request.getRequestDispatcher("/wwpass");
                RequestDispatcherObject.forward(request, response); // Clear the current session and refresh. Not fully functional, as ticket is not removed from GET request
            }
        }
    }

    /**************************************Read/Write testing*********************************************************
     Here we will test writeData and readData functions to make sure that data is not corrupted.
     We will test Latin, Cyrillic, Han simplified, Han traditional, Arabic and Turkish characters.
     ******************************************************************************************************************/

    int i = 0;

    //----------------------------Function for read/write testing---------------------------------------------------------
    public void tester() throws Exception {
        WWPassConnection cls = new WWPassConnection(certfile, keyfile);
        BufferedWriter out = new BufferedWriter(new FileWriter("/file.txt"));

        //--------------------------------------Latin testing-------------------------------------------------------------
        String Daniil = "Daniil";
        cls.writeData(newTicket, Daniil);
        byteriser(Daniil);
        System.out.println("Written data: Daniil");
        out.write("Written Data: Daniil");
        out.newLine();

        String data = cls.readData(newTicket);
        i = i - 1;
        byteriser(data);
        System.out.println("Latin Data: " + data);
        out.write("Latin Data: " + data);
        out.newLine();
        if (data.equals(Daniil)) {
            out.write("Latin - OK");
            out.newLine();
        } else {
            out.write("Latin - Fail");
            out.newLine();
        }

        //--------------------------------------Cyrillic testing-------------------------------------------------------------
        Daniil = "Даниил";
        System.out.println("Written data: Даниил");
        cls.writeData(newTicket, "Даниил");
        out.write("Written Data: Даниил");
        out.newLine();

        data = cls.readData(newTicket);
        System.out.println("Cyrillic Data: " + data);
        byteriser(Daniil);
        i = i - 1;
        byteriser(data);
        out.write("Cyrillic Data: " + data);
        out.newLine();
        if (data.equals(Daniil)) {
            out.write("Cyrillic - OK");
            out.newLine();
        } else {
            out.write("Cyrillic - Fail");
            out.newLine();
        }

        //------------------------------------Han simplified testing---------------------------------------------------------------------------
        Daniil = "达尼尔";
        System.out.println("Written data: 达尼尔");
        cls.writeData(newTicket, "达尼尔");
        out.write("Written data: 达尼尔");
        out.newLine();

        data = cls.readData(newTicket);
        System.out.println("Han Data: " + data);
        byteriser(Daniil);
        i = i - 1;
        byteriser(data);

        out.write("Han Data: " + data);
        out.newLine();
        if (data.equals(Daniil)) {
            out.write("Chinese - OK");
            out.newLine();
        } else {
            out.write("Chinese - Fail");
            out.newLine();
        }

        //---------------------------------Han traditional testing------------------------------------------------------------------------------
        Daniil = "達尼爾";
        cls.writeData(newTicket, "達尼爾");
        out.write("Written Data: 達尼爾");
        out.newLine();

        data = cls.readData(newTicket);
        byteriser(Daniil);
        i = i - 1;
        byteriser(data);
        out.write("Han Traditional Data: " + data);
        out.newLine();
        if (data.equals(Daniil)) {
            out.write("Han Traditional - OK");
            out.newLine();
        } else {
            out.write("Han Traditional - Fail");
            out.newLine();
        }

        //--------------------------------------Arabic testing-------------------------------------------------------------
        Daniil = "دانيل";
        cls.writeData(newTicket, "دانيل");
        out.write("Written Data: دانيل");
        out.newLine();

        data = cls.readData(newTicket);
        byteriser(Daniil);
        i = i - 1;
        byteriser(data);
        out.write("Arabic Data: " + data);
        out.newLine();
        if (data.equals(Daniil)) {
            out.write("Arabic - OK");
            out.newLine();
        } else {
            out.write("Arabic - Fail");
            out.newLine();
        }

        //--------------------------------------Turkish testing-------------------------------------------------------------
        Daniil = "gün batımı";
        cls.writeData(newTicket, "gün batımı");
        out.write("Written Data: gün batımı");
        out.newLine();

        data = cls.readData(newTicket);
        byteriser(Daniil);
        i = i - 1;
        byteriser(data);
        out.write("Turkish Data: " + data);
        out.newLine();
        if (data.equals(Daniil)) {
            out.write("Turkish - OK");
            out.newLine();
        } else {
            out.write("Turkish - Fail");
            out.newLine();
        }

        out.flush();
        out.close();

        //****************************************Testing over**************************************************************************
    }

    //----------------------------Function for outputting data as bytes---------------------------------------------------
    public void byteriser(String data) throws IOException {
        FileWriter out1 = new FileWriter("/bytes.txt", true);
        i = i + 1;
        byte[] byte_data = data.getBytes(StandardCharsets.UTF_8);
        out1.write(i + ": " + Arrays.toString(byte_data) + "\n");
        out1.close();
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
     */
    @SuppressWarnings({"EmptyMethod", "RedundantThrows"})
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // TODO Auto-generated method stub
    }
}
