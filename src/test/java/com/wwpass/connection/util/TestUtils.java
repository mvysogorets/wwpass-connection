package com.wwpass.connection.util;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;
import java.util.Scanner;

/**
 * TestUtils.java
 *
 * WWPass Client Library
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
public class TestUtils {
	
	private static String shellCommand;
	private static String shellCommandWithP;
	private static String spName;
	private static String password;
	
	static {
		try {
			Properties props = new Properties();
			
			props.load(ClassLoader.class.getResourceAsStream("/setup.properties"));
			
			shellCommand = props.getProperty("SHELL_COMMAND");
			shellCommandWithP = props.getProperty("SHELL_COMMAND_WITH_P");
			spName = props.getProperty("SP_NAME");
			password = props.getProperty("PASSWORD");
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public String getTicket() throws IOException, InterruptedException{
		return getTicketFromShell(shellCommand + " " + spName);
	}
	
	public String getTicketWithP() throws IOException, InterruptedException {
		return getTicketFromShell((shellCommandWithP + " " + spName + ":p").replace("password",password));
	}
	
	public String authenticateTicket(String ticket) throws IOException, InterruptedException {
		return getTicketFromShell(shellCommand + " " + ticket);
	}
	
	public String authenticateTicketWithP(String ticket) throws IOException, InterruptedException {
		return getTicketFromShell((shellCommandWithP + " " + ticket).replace("password",password));
	}
	
	private String getTicketFromShell(String command) throws IOException, InterruptedException {
		
		Process p = null;
		Scanner scanner = null;
		StringBuffer sb = new StringBuffer();
		try {
			p = Runtime.getRuntime().exec(command);
			p.waitFor();
			scanner = new Scanner(p.getInputStream());
				
			while(scanner.hasNextLine()) {
				sb.append(scanner.nextLine());
			}
			
			return sb.toString();
		} finally {
			scanner.close();
			p.destroy();
			sb = null;
		}
	}

}
