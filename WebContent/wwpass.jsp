<%@page import="com.wwpass.wwpass"%>

<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <!-- Load the WWPass JS library -->
    <script type="text/javascript" src="http://cdn.wwpass.com/packages/wwpass.js/1.3/wwpass.js"></script>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <title>WWPass</title>
</head>
<body>

<script type="text/javascript">  

//--------------JS function to set the informational message---------------------------------------------------------------------------
function wwp_set_msg(message, header) {
    var message = message || '';
    var header = header || '';
    document.getElementById('wwp-message-header').innerHTML = header;
    document.getElementById('wwp-message-p').innerHTML = message;
}

//--------------JS function to get ticket or error------------------------------------------------------------------------------------
function auth_cb(status, ticket_or_reason) {
    if(status == WWPass_OK) {                                                           // If ticket request handled successfully
        wwp_set_msg('Success', 'WWPass Authentication');                                // Set info message
        window.location.href = 'wwpass?ticket=' + encodeURIComponent(ticket_or_reason); // Pass ticket to the auth.java and call it
    } else {
        wwp_set_msg(ticket_or_reason+' ('+status+')', 'Authentication failed');         // If ticket request not handled, return error
    }
}

//----------------JS function called when login button is clicked--------------------------------------------------------------------
function token_auth() {
    wwp_set_msg('WWPass Authentication in progress..'); // Set the info message
    wwpass_auth("${SP_name}", auth_cb);                 // Get SP_name from auth.java and use it to generate ticket
}

</script> 

<!--*************** Display the login button and informational text fields ********************************-->    
<img src="C:\\images\\loginwWWP-257x56.png"
     alt="Login with WWPass" 
     onmousedown="this.src='C:\\images\\loginwWWP-257x56_mouseover.png';"
     onmouseup="this.src='C:\\images\\loginwWWP-257x56.png';"
     onclick="token_auth()"
    >
    <p id="wwp-message-header"></p>
    <p id="wwp-message-p"></p>

<!--********************************************************************************************************-->    

</body>
</html>
