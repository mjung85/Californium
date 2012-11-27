/*******************************************************************************
 * Copyright (c) 2012, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * This file is part of the Californium (Cf) CoAP framework.
 ******************************************************************************/
/**
 * 
 */
package ch.ethz.inf.vs.californium.examples;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;

import ch.ethz.inf.vs.californium.coap.*;
import ch.ethz.inf.vs.californium.coap.registries.CodeRegistry;
import ch.ethz.inf.vs.californium.coap.registries.MediaTypeRegistry;
import ch.ethz.inf.vs.californium.coap.registries.OptionNumberRegistry;
import ch.ethz.inf.vs.californium.endpoint.resources.RemoteResource;
import ch.ethz.inf.vs.californium.endpoint.resources.Resource;
import ch.ethz.inf.vs.californium.util.Log;

/**
 * Class container of the tests.
 * 
 * @author Francesco Corazza
 */
public class PlugtestClient {
    
    protected static final int PLUGTEST_BLOCK_SIZE = 64;

    /** The server uri. */
    private String serverURI = null;

    /** The test map. */
    private final Map<String, Class<?>> testMap = new HashMap<String, Class<?>>();

    /** The test list. */
    protected List<String> testsToRun = new ArrayList<String>();
    
    /** The test summary. */
    protected List<String> summary = new ArrayList<String>();

    /**
     * Default constructor. Loads with reflection each nested class that is a
     * derived type of TestClientAbstract.
     * 
     * @param serverURI
     *            the server uri
     */
    public PlugtestClient(String serverURI) {
        if (serverURI == null || serverURI.isEmpty()) {
            System.err.println("serverURI == null || serverURI.isEmpty()");
            throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
        }
        this.serverURI = serverURI;

        // fill the map with each nested class not abstract that instantiate
        // TestClientAbstract
        for (Class<?> clientTest : this.getClass().getDeclaredClasses()) {
            if (!Modifier.isAbstract(clientTest.getModifiers()) && (clientTest.getSuperclass() == TestClientAbstract.class)) {

                this.testMap.put(clientTest.getSimpleName(), clientTest);
            }
        }

        // DEBUG System.out.println(this.testMap.size());
    }

    /**
     * Instantiates the given testNames or if null all tests implemented.
     * 
     * @param testNames
     *            the test names
     */
    public void instantiateTests(String... testNames) {
        
        testsToRun = Arrays.asList( (testNames==null || testNames.length==0) ? this.testMap.keySet().toArray(testNames) : testNames);
        Collections.sort(testsToRun);
        
        try {
            // iterate for each chosen test
            for (String testString : testsToRun) {
                // DEBUG System.out.println(testString);

                // get the corresponding class
                Class<?> testClass = this.testMap.get(testString);
                if (testClass == null) {
                    System.err.println("testClass for '"+testString+"' == null");
                    System.exit(-1);
                }

                // get the unique constructor
                Constructor<?>[] constructors = testClass.getDeclaredConstructors();

                if (constructors.length == 0) {
                    System.err.println("constructors.length == 0");
                    System.exit(-1);
                }
                
                // inner class: first argument (this) is the enclosing instance
                @SuppressWarnings("unused")
                TestClientAbstract testClient = (TestClientAbstract) constructors[0].newInstance(this, serverURI);
            }
            
            waitForTests();
            
            // summary
            System.out.println("\n==== SUMMARY ====");
            for (String result : summary) {
                System.out.println(result);
            }
            
        } catch (InstantiationException e) {
            System.err.println("Reflection error");
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            System.err.println("Reflection error");
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            System.err.println("Reflection error");
            e.printStackTrace();
        } catch (SecurityException e) {
            System.err.println("Reflection error");
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            System.err.println("Reflection error");
            e.printStackTrace();
        } catch (InterruptedException e) {
            System.err.println("Concurrency error");
            e.printStackTrace();
        }
    }
    
    public synchronized void waitForTests() throws InterruptedException {
        while (summary.size()<testsToRun.size()) {
            wait();
        }
    }
    
    public synchronized void tickOffTest() {
        notify();
    }
    
    public synchronized void addSummaryEntry(String entry) {
        summary.add(entry);
    }

    /**
     * Main entry point.
     * 
     * @param args
     *            the arguments
     */
    public static void main(String[] args) {
		if (args.length == 0 || !args[0].startsWith("coap://")) {
            System.out.println("Californium (Cf) Plugtest Client");
            System.out.println("(c) 2012, Institute for Pervasive Computing, ETH Zurich");
            System.out.println();
            System.out.println("Usage: " + PlugtestClient.class.getSimpleName() + " URI [TESTNAMES...]");
			System.out.println("  URI       : The CoAP URI of the Plugtest server to test (coap://...)");
            System.out.println("  TESTNAMES : A list of specific tests to run, omit to run all");
            System.out.println();
            System.out.println("Available tests:");
            System.out.print(" ");
            for (Class<?> clientTest : PlugtestClient.class.getDeclaredClasses()) {
                if (!Modifier.isAbstract(clientTest.getModifiers()) && (clientTest.getSuperclass() == TestClientAbstract.class)) {
                    System.out.print(" " + clientTest.getSimpleName());
                }
            }
            System.exit(-1);
        }
        
        Log.setLevel(Level.WARNING);
        Log.init();
        
        // default block size
        CommunicatorFactory.getInstance().setTransferBlockSize(PLUGTEST_BLOCK_SIZE);

        // create the factory with the given server URI
        PlugtestClient clientFactory = new PlugtestClient(args[0]);

        // instantiate the chosen tests
        clientFactory.instantiateTests(Arrays.copyOfRange(args, 1, args.length));
    }

    /**
     * Abstract class to support various test client implementations.
     * 
     * @author Francesco Corazza
     */
    public abstract class TestClientAbstract {

        /** The test name. */
        protected String testName = null;

        /** The verbose. */
        protected boolean verbose = false;
        
        /** Use synchronous or asynchronous requests. Sync recommended due to single threaded servers and slow resources. */
        protected boolean sync = true;

        /**
         * Instantiates a new test client abstract.
         * 
         * @param testName
         *            the test name
         * @param verbose
         *            the verbose
         */
        public TestClientAbstract(String testName, boolean verbose, boolean synchronous) {
            if (testName == null || testName.isEmpty()) {
                throw new IllegalArgumentException("testName == null || testName.isEmpty()");
            }

            this.testName = testName;
            this.verbose = verbose;
            this.sync = synchronous;
        }

        /**
         * Instantiates a new test client abstract.
         * 
         * @param testName
         *            the test name
         */
        public TestClientAbstract(String testName) {
            this(testName, false, true);
        }

        /**
         * Execute request.
         * 
         * @param request
         *            the request
         * @param serverURI
         *            the server uri
         * @param resourceUri
         *            the resource uri
         * @param payload
         *            the payload
         */
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                System.err.println("serverURI == null || serverURI.isEmpty()");
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                System.err.println("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }
            
            request.registerResponseHandler(new TestResponseHandler());

            // enable response queue for synchronous I/O
            if (sync) {
                request.enableResponseQueue(true);
            }

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                request.execute();
                if (sync) {
                    request.receiveResponse();
                }
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        /**
         * The Class TestResponseHandler.
         */
        protected class TestResponseHandler implements ResponseHandler {

            /**
             * @see ch.ethz.inf.vs.californium.coap.ResponseHandler#handleResponse(ch.ethz.inf.vs.californium.coap.Response)
             */
            @Override
            public void handleResponse(Response response) {

                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");

                // checking the response
                if (response!=null) {

                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): "
                                + response.getRTT());
                        response.prettyPrint();
                    }
                    
                    System.out.println("**** BEGIN CHECK ****");

                    if (checkResponse(response.getRequest(), response)) {
                        System.out.println("**** TEST PASSED ****");
                        addSummaryEntry(testName + ": PASSED");
                    } else {
                        System.out.println("**** TEST FAILED ****");
                        addSummaryEntry(testName + ": FAILED");
                    }
                    
                    tickOffTest();
                }
                
            }
        }

        /**
         * Check response.
         * 
         * @param request
         *            the request
         * @param response
         *            the response
         * @return true, if successful
         */
        protected abstract boolean checkResponse(Request request, Response response);

        /**
         * Check int.
         * 
         * @param expected
         *            the expected
         * @param actual
         *            the actual
         * @param fieldName
         *            the field name
         * @return true, if successful
         */
        protected boolean checkInt(int expected, int actual, String fieldName) {
            boolean success = expected == actual;

            if (!success) {
                System.out.println("FAIL: Expected " + fieldName + ": " + expected + ", but was: " + actual);
            } else {
                System.out.println("PASS: Correct " + fieldName + String.format(" (%d)", actual));
            }

            return success;
        }
        
        /**
         * Check int.
         * 
         * @param expected
         *            the expected
         * @param actual
         *            the actual
         * @param fieldName
         *            the field name
         * @return true, if successful
         */
        protected boolean checkInts(int[] expected, int actual, String fieldName) {
        	boolean success = false;
        	for (int i : expected) {
				if (i == actual) {
					success = true;
					break;
				}
			}

            if (!success) {
                System.out.println("FAIL: Expected " + fieldName + ": " + Arrays.toString(expected) + ", but was: " + actual);
            } else {
                System.out.println("PASS: Correct " + fieldName + String.format(" (%d)", actual));
            }

            return success;
        }
        
        /**
         * Check String.
         * 
         * @param expected
         *            the expected
         * @param actual
         *            the actual
         * @param fieldName
         *            the field name
         * @return true, if successful
         */
        protected boolean checkString(String expected, String actual, String fieldName) {
            boolean success = expected.equals(actual);

            if (!success) {
                System.out.println("FAIL: Expected " + fieldName + ": " + expected + ", but was: " + actual);
            } else {
                System.out.println("PASS: Correct " + fieldName + " \"" + actual + "\"");
            }

            return success;
        }

        /**
         * Check type.
         * 
         * @param expectedMessageType
         *            the expected message type
         * @param actualMessageType
         *            the actual message type
         * @return true, if successful
         */
        protected boolean checkType(Message.messageType expectedMessageType, Message.messageType actualMessageType) {
            boolean success = expectedMessageType.equals(actualMessageType);

            if (!success) {
                System.out.printf("FAIL: Expected type %s, but was %s\n", expectedMessageType, actualMessageType);
            } else {
                System.out.printf("PASS: Correct type (%s)\n", actualMessageType.toString());
            }

            return success;
        }
        
        /**
         * Check types.
         * 
         * @param expectedMessageTypes
         *            the expected message types
         * @param actualMessageType
         *            the actual message type
         * @return true, if successful
         */
        protected boolean checkTypes(Message.messageType[] expectedMessageTypes, Message.messageType actualMessageType) {
            boolean success = false;
            for (Message.messageType messageType : expectedMessageTypes) {
				if (messageType.equals(actualMessageType)) {
					success = true;
					break;
				}
			}

            if (!success) {
            	StringBuilder sb = new StringBuilder();
            	for (Message.messageType messageType : expectedMessageTypes) {
					sb.append(", " + messageType.toString());
				}
            	sb.delete(0, 2); // delete the first ", "
         
                System.out.printf("FAIL: Expected type %s, but was %s\n", "[ " + sb.toString() + " ]", actualMessageType);
            } else {
                System.out.printf("PASS: Correct type (%s)\n", actualMessageType.toString());
            }

            return success;
        }

        /**
         * Checks for Content-Type option.
         * 
         * @param response
         *            the response
         * @return true, if successful
         */
        protected boolean hasContentType(Response response) {
            boolean success = response.hasOption(OptionNumberRegistry.CONTENT_TYPE);

            if (!success) {
                System.out.println("FAIL: Response without Content-Type");
            } else {
                System.out.printf("PASS: Content-Type (%s)\n", MediaTypeRegistry.toString(response.getContentType()));
            }

            return success;
        }

        /**
         * Checks for Location-Path option.
         * 
         * @param response
         *            the response
         * @return true, if successful
         */
        protected boolean hasLocation(Response response) {
            boolean success = response.hasOption(OptionNumberRegistry.LOCATION_PATH);

            if (!success) {
                System.out.println("FAIL: Response without Location");
            } else {
                System.out.printf("PASS: Location (%s)\n", response.getLocationPath());
            }

            return success;
        }
        
        /**
         * Checks for ETag option.
         * 
         * @param response
         *            the response
         * @return true, if successful
         */
        protected boolean hasEtag(Response response) {
            boolean success = response.hasOption(OptionNumberRegistry.ETAG);

            if (!success) {
                System.out.println("FAIL: Response without Etag");
            } else {
                System.out.printf("PASS: Etag (%s)\n", Option.hex(response.getEtag()));
            }

            return success;
        }
        
        /**
         * Checks for Max-Age option.
         * 
         * @param response
         *            the response
         * @return true, if successful
         */
        protected boolean hasMaxAge(Response response) {
            boolean success = response.hasOption(OptionNumberRegistry.MAX_AGE);

            if (!success) {
                System.out.println("FAIL: Response without Max-Age");
            } else {
                System.out.printf("PASS: Max-Age (%s)\n", response.getMaxAge());
            }

            return success;
        }
        
        /**
         * Checks for Location-Query option.
         * 
         * @param response
         *            the response
         * @return true, if successful
         */
        protected boolean hasLocationQuery(Response response) {
            boolean success = response.hasOption(OptionNumberRegistry.LOCATION_QUERY);

            if (!success) {
                System.out.println("FAIL: Response without Location-Query");
            } else {
                System.out.printf("PASS: Location-Query (%s)\n", response.getLocationQuery());
            }

            return success;
        }
        
        /**
         * Checks for Token option.
         * 
         * @param response
         *            the response
         * @return true, if successful
         */
        protected boolean hasToken(Response response) {
            boolean success = response.hasOption(OptionNumberRegistry.TOKEN);

            if (!success) {
                System.out.println("FAIL: Response without Token");
            } else {
                System.out.printf("PASS: Token (%s)\n", Option.hex(response.getToken()));
            }

            return success;
        }
        
        /**
         * Checks for absent Token option.
         * 
         * @param response
         *            the response
         * @return true, if successful
         */
        protected boolean hasNoToken(Response response) {
            boolean success = !response.hasOption(OptionNumberRegistry.TOKEN);

            if (!success) {
                System.out.println("FAIL: Response with Token");
            } else {
                System.out.printf("PASS: No Token\n");
            }

            return success;
        }

        /**
         * Checks for Observe option.
         * 
         * @param response
         *            the response
         * @return true, if successful
         */
        protected boolean hasObserve(Response response, boolean invert) {
            boolean success = response.hasOption(OptionNumberRegistry.OBSERVE);
            
            // invert to check for not having the option
            success ^= invert;

            if (!success) {
                System.out.println("FAIL: Response without Observe");
            } else if (!invert) {
                System.out.printf("PASS: Observe (%d)\n", response.getFirstOption(OptionNumberRegistry.OBSERVE).getIntValue());
            } else {
                System.out.println("PASS: No Observe");
            }

            return success;
        }
        protected boolean hasObserve(Response response) {
            return hasObserve(response, false);
        }
        
        protected boolean checkOption(Option expextedOption, Option actualOption) {
            boolean success = actualOption!=null && expextedOption.getOptionNumber()==actualOption.getOptionNumber();
            
            if (!success) {
                System.out.printf("FAIL: Missing option nr %d\n", expextedOption.getOptionNumber());
            } else {
                
                // raw value byte array can be different, although value is the same 
                success &= expextedOption.toString().equals(actualOption.toString());
                
                if (!success) {
                    System.out.printf("FAIL: Expected %s, but was %s\n", expextedOption.toString(), actualOption.toString());
                } else {
                    System.out.printf("PASS: Correct option (%s)\n", actualOption.toString());
                }
            }
            
            return success;
        }
        
        protected boolean checkDifferentOption(Option expextedOption, Option actualOption) {
            boolean success = actualOption!=null && expextedOption.getOptionNumber()==actualOption.getOptionNumber();
            
            if (!success) {
                System.out.printf("FAIL: Missing option nr %d\n", expextedOption.getOptionNumber());
            } else {
                
                // raw value byte array can be different, although value is the same 
                success &= !expextedOption.toString().equals(actualOption.toString());
                
                if (!success) {
                    System.out.printf("FAIL: Expected difference, but was %s\n", actualOption.toString());
                } else {
                    System.out.printf("PASS: Expected not %s and was %s\n", expextedOption.toString(), actualOption.toString());
                }
            }
            
            return success;
        }

        /**
         * Check token.
         * 
         * @param expectedToken the expected token
         * @param actualToken the actual token
         * @return true, if successful
         */
        protected boolean checkToken(Option expextedOption, Option actualOption) {
            
            boolean success = true;
            
            if (expextedOption.equals(new Option(TokenManager.emptyToken, OptionNumberRegistry.TOKEN))) {
                
                success = actualOption==null;

                if (!success) {
                    System.out.printf("FAIL: Expected empty token, but was %s\n", actualOption);
                } else {
                    System.out.println("PASS: Correct empty token");
                }
                
                return success;
                
            } else {
                
                success = actualOption.getRawValue().length <=8;
                success &= actualOption.getRawValue().length >= 1;

                // eval token length
                if (!success) {
                    System.out.printf("FAIL: Expected token %s, but %s has illeagal length\n", expextedOption, actualOption);
                    return success;
                }
                
                success &= expextedOption.toString().equals(actualOption.toString());

                if (!success) {
                    System.out.printf("FAIL: Expected token %s, but was %s\n", expextedOption, actualOption);
                } else {
                    System.out.printf("PASS: Correct token (%s)\n", actualOption);
                }
                
                return success;
            }
        }
        
        /**
         * Check discovery.
         * 
         * @param expextedAttribute
         *              the resource attribute to filter
         * @param actualDiscovery
         *              the reported Link Format
         * @return true, if successful
         */
        protected boolean checkDiscovery(String expextedAttribute, String actualDiscovery) {
            
            Resource res = RemoteResource.newRoot(actualDiscovery);

            List<Option> query = new ArrayList<Option>();
            query.add(new Option(expextedAttribute, OptionNumberRegistry.URI_QUERY));
            
            boolean success = true;
            
            for (Resource sub : res.getSubResources()) {
                success &= LinkFormat.matches(sub, query);
                
                if (!success) {
                    System.out.printf("FAIL: Expected %s, but was %s\n", expextedAttribute, LinkFormat.serialize(sub, null, false));
                }
            }
            
            if (success) {
                System.out.println("PASS: Correct Link Format filtering");
            }
            
            return success;
        }

    }

    /**
     * TD_COAP_CORE_01:
     * Perform GET transaction (CON mode).
     * 
     * @author Francesco Corazza and Matthias Kovatsch
     */
    public class CC01 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        
        public CC01(String serverURI) {
            super(CC01.class.getSimpleName());

            // create the request
            Request request = new GETRequest();

            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkInt(request.getMID(), response.getMID(), "MID");
            success &= hasContentType(response);

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_02:
     * Perform DELETE transaction (CON mode).
     * 
     * @author Francesco Corazza and Matthias Kovatsch
     */
    public class CC02 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_DELETED;

        public CC02(String serverURI) {
            super(CC02.class.getSimpleName());

            // create the request
            Request request = new DELETERequest();
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkInt(request.getMID(), response.getMID(), "MID");

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_03:
     * Perform PUT transaction (CON mode).
     * 
     * @author Francesco Corazza and Matthias Kovatsch
     */
    public class CC03 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
		private final int[] expectedResponseCodes = new int[] { CodeRegistry.RESP_CREATED, CodeRegistry.RESP_CHANGED };

        public CC03(String serverURI) {
            super(CC03.class.getSimpleName());

            // create the request
            Request request = new PUTRequest();
            // add payload
            request.setPayload("TD_COAP_CORE_03", MediaTypeRegistry.TEXT_PLAIN);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            // Code = 68 (2.04 Changed) or 65 (2.01 Created)
            success &= checkInts(expectedResponseCodes, response.getCode(), "code");
            success &= checkInt(request.getMID(), response.getMID(), "MID");

            return success;
        }
    }

    /**
     * TD_COAP_CORE_04:
     * Perform POST transaction (CON mode).
     * 
     * @author Francesco Corazza and Matthias Kovatsch
     */
    public class CC04 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
		private final int[] expectedResponseCodes = new int[] { CodeRegistry.RESP_CREATED, CodeRegistry.RESP_CHANGED };

        public CC04(String serverURI) {
            super(CC04.class.getSimpleName());

            // create the request
            Request request = new POSTRequest();
            // add payload
            request.setPayload("TD_COAP_CORE_04", MediaTypeRegistry.TEXT_PLAIN);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            // Code = 65(2.01 Created) or 68 (2.04 changed)
            success &= checkInts(expectedResponseCodes, response.getCode(), "code");
            success &= checkInt(request.getMID(), response.getMID(), "MID");

            return success;
        }
    }

    /**
     * TD_COAP_CORE_05:
     * Perform GET transaction (NON mode).
     * 
     * @author Francesco Corazza and Matthias Kovatsch
     */
    public class CC05 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC05(String serverURI) {
            super(CC05.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, false);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.NON, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasContentType(response);

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_06:
     * Perform DELETE transaction (NON mode).
     * 
     * @author Francesco Corazza and Matthias Kovatsch
     */
    public class CC06 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_DELETED;

        public CC06(String serverURI) {
            super(CC06.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_DELETE, false);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.NON, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");

            return success;
        }
    }

    /**
     * TD_COAP_CORE_07:
     * Perform PUT transaction (NON mode).
     * 
     * @author Francesco Corazza and Matthias Kovatsch
     */
    public class CC07 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        private final int[] expectedResponseCodes = new int[] {CodeRegistry.RESP_CREATED, CodeRegistry.RESP_CHANGED};

        public CC07(String serverURI) {
            super(CC07.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_PUT, false);
            // add payload
            request.setPayload("TD_COAP_CORE_07", MediaTypeRegistry.TEXT_PLAIN);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.NON, response.getType());
            // Code = 68 (2.04 Changed) or 65 (2.01 Created)
            success &= checkInts(expectedResponseCodes, response.getCode(), "code");

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_08:
     * Perform POST transaction (NON mode).
     * 
     * @author Francesco Corazza and Matthias Kovatsch
     */
    public class CC08 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        private final int[] expectedResponseCodes = new int[] {CodeRegistry.RESP_CREATED, CodeRegistry.RESP_CHANGED};

        public CC08(String serverURI) {
            super(CC08.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_POST, false);
            // add payload
            request.setPayload("TD_COAP_CORE_08", MediaTypeRegistry.TEXT_PLAIN);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.NON, response.getType());
            // Code = 65(2.01 Created) or 68 (2.04 changed)
            success &= checkInts(expectedResponseCodes, response.getCode(), "code");

            return success;
        }
    }

    /**
     * TD_COAP_CORE_09:
     * Perform GET transaction with separate response (CON mode, no piggyback)
     * 
     * @author Matthias Kovatsch
     */
    public class CC09 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/separate";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC09(String serverURI) {
            super(CC09.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;
            
            success &= checkType(Message.messageType.CON, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasContentType(response);

            return success;
        }
    }

    /**
     * TD_COAP_CORE_10:
     * Handle request containing Token option.
     * 
     * @author Matthias Kovatsch
     */
    public class CC10 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC10(String serverURI) {
            super(CC10.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
			request.setToken(TokenManager.getInstance().acquireToken(false)); // not preferring empty token
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkToken(request.getFirstOption(OptionNumberRegistry.TOKEN), response.getFirstOption(OptionNumberRegistry.TOKEN));
            success &= hasContentType(response);

            return success;
        }
    }

    /**
     * TD_COAP_CORE_11:
     * Handle request not containing Token option.
     * 
     * @author Matthias Kovatsch
     */
    public class CC11 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC11(String serverURI) {
            super(CC11.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // Length of the token should be between 1 to 8 B
			request.setToken(TokenManager.getInstance().acquireToken(false));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            // Token value = the same value as in the request sent by the client in step 2
            success &= checkToken(request.getFirstOption(OptionNumberRegistry.TOKEN), response.getFirstOption(OptionNumberRegistry.TOKEN));
            success &= hasContentType(response);

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_12:
     * Perform GET transaction not containing Token option (CON mode)
     * 
     * @author Matthias Kovatsch
     */
    public class CC12 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC12(String serverURI) {
            super(CC12.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            request.requiresToken(false);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasNoToken(response);
            success &= hasContentType(response);

            return success;
        }
    }

    /**
     * TD_COAP_CORE_13
     * Handle request containing several Uri-Path options.
     * 
     * @author Matthias Kovatsch
     */
    public class CC13 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/seg1/seg2/seg3";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC13(String serverURI) {
            super(CC13.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasContentType(response);

            return success;
        }
    }

    /**
     * TD_COAP_CORE_14:
     * Handle request containing several Uri-Query options.
     * 
     * @author Matthias Kovatsch
     */
    public class CC14 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/query";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC14(String serverURI) {
            super(CC14.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // add query
            request.setOption(new Option("first=1", OptionNumberRegistry.URI_QUERY));
            request.addOption(new Option("second=2", OptionNumberRegistry.URI_QUERY));
            request.addOption(new Option("third=3", OptionNumberRegistry.URI_QUERY));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;
            
			success &= checkTypes(new Message.messageType[] { Message.messageType.ACK, Message.messageType.CON }, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasContentType(response);

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_15:
     * Perform GET transaction (CON mode, piggybacked response) in a lossy context
     * 
     * @author Matthias Kovatsch
     */
    public class CC15 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC15(String serverURI) {
            super(CC15.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            executeRequest(request, serverURI, RESOURCE_URI);
            
            // TODO
            // Repeat steps 1-4 until at least one of the following actions has been observed:
            // •	One dropped request
            // •	One dropped response

        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;
            
			success &= checkTypes(new Message.messageType[] { Message.messageType.ACK, Message.messageType.CON }, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasContentType(response);

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_16:
     * Perform GET transaction (CON mode, delayed response) in a lossy context
     * 
     * @author Matthias Kovatsch
     */
    public class CC16 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/separate";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC16(String serverURI) {
            super(CC16.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            request.setToken(TokenManager.getInstance().acquireToken(false));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
            
            // TODO Repeat steps 1-6 until at least one of the following actions has been observed:
            //	•	One dropped request
            //	•	One dropped request ACK 
            //	•	One dropped response

        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;
            
            success &= checkType(Message.messageType.CON, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasContentType(response);
            success &= checkOption(request.getFirstOption(OptionNumberRegistry.TOKEN), response.getFirstOption(OptionNumberRegistry.TOKEN));

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_17:
     * Perform GET transaction with delayed response (NON mode).
     * 
     * @author Matthias Kovatsch
     */
    public class CC17 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/separate";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC17(String serverURI) {
            super(CC17.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, false);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.NON, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasContentType(response);

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_18:
     * Perform POST transaction with responses containing several Location-Path options (CON mode)
     * 
     * @author Matthias Kovatsch
     */
    public class CC18 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CREATED;

        public CC18(String serverURI) {
            super(CC18.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_POST, true);
            // add payload
            request.setPayload("TD_COAP_CORE_18", MediaTypeRegistry.TEXT_PLAIN);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasLocation(response);
            
            List<Option> options = response.getOptions(OptionNumberRegistry.LOCATION_PATH);
            success &= checkOption(new Option("location1", OptionNumberRegistry.LOCATION_PATH), options.get(0));
            success &= checkOption(new Option("location2", OptionNumberRegistry.LOCATION_PATH), options.get(1));
            success &= checkOption(new Option("location3", OptionNumberRegistry.LOCATION_PATH), options.get(2));

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_18:
     * Perform POST transaction with responses containing several Location-Query options (CON mode)
     * 
     * @author Matthias Kovatsch
     */
    public class CC19 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/location-query";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CREATED;

        public CC19(String serverURI) {
            super(CC19.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_POST, true);
            // add payload
            request.setPayload("TD_COAP_CORE_19", MediaTypeRegistry.TEXT_PLAIN);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasLocationQuery(response);
            
            List<Option> options = response.getOptions(OptionNumberRegistry.LOCATION_QUERY);
            success &= checkOption(new Option("first=1", OptionNumberRegistry.LOCATION_QUERY), options.get(0));
            success &= checkOption(new Option("second=2", OptionNumberRegistry.LOCATION_QUERY), options.get(1));

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_20:
     * Perform GET transaction containing the Accept option (CON mode)
     * 
     * @author Matthias Kovatsch
     */
    public class CC20 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/multi-format";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC20(String serverURI) {
            super(CC20.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            request.setOption(new Option(MediaTypeRegistry.TEXT_PLAIN, OptionNumberRegistry.ACCEPT));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                // Part A
                request.execute();
                response = request.receiveResponse();
                
                // checking the response
                if (response != null) {
                	
                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): " + response.getRTT());
                        response.prettyPrint();
                    }
                	
                    success &= checkType(Message.messageType.ACK, response.getType());
    	            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
    				success &= checkOption(new Option(MediaTypeRegistry.TEXT_PLAIN, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
					
					// Part B
    				request = new Request(CodeRegistry.METHOD_GET, true);
    	            request.setOption(new Option(MediaTypeRegistry.APPLICATION_XML, OptionNumberRegistry.ACCEPT));

					request.setURI(uri);
		            if (request.requiresToken()) {
		                request.setToken(TokenManager.getInstance().acquireToken());
		            }

		            // enable response queue for synchronous I/O
		            request.enableResponseQueue(true);
		            
	                request.execute();
	                response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                    	
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }
                    	
                        success &= checkType(Message.messageType.ACK, response.getType());
        	            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
        				success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_XML, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
                        
                    }
                }
                
                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
			return false;
        }

    }
    
    /**
     * TD_COAP_CORE_21:
     * Perform GET transaction containing the ETag option (CON mode)
     * 
     * @author Matthias Kovatsch
     */
    public class CC21 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE_A = CodeRegistry.RESP_CONTENT;
        public static final int EXPECTED_RESPONSE_CODE_B = CodeRegistry.RESP_VALID;
        public static final int EXPECTED_RESPONSE_CODE_C = CodeRegistry.RESP_CONTENT;
        
        private byte[] etagStep3;
        

        public CC21(String serverURI) {
            super(CC21.class.getSimpleName());

			Request request = new Request(CodeRegistry.METHOD_GET, true);
			executeRequest(request, serverURI, RESOURCE_URI);
			
		}
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                // Part A
                request.execute();
                response = request.receiveResponse();
                
                // checking the response
                if (response != null) {
                	
                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): " + response.getRTT());
                        response.prettyPrint();
                    }
                	
					success &= checkType(Message.messageType.ACK, response.getType());
					success &= checkInt(EXPECTED_RESPONSE_CODE_A, response.getCode(), "code");
					success &= hasEtag(response);
					etagStep3 = response.getFirstOption(OptionNumberRegistry.ETAG).getRawValue();
					
					// Part B
					request = new Request(CodeRegistry.METHOD_GET, true);
					request.setOption(new Option(etagStep3, OptionNumberRegistry.ETAG));

					request.setURI(uri);
		            if (request.requiresToken()) {
		                request.setToken(TokenManager.getInstance().acquireToken());
		            }

		            // enable response queue for synchronous I/O
		            request.enableResponseQueue(true);
		            
	                request.execute();
	                response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                    	
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }
                    	
        				success &= checkType(Message.messageType.ACK, response.getType());
        				success &= checkInt(EXPECTED_RESPONSE_CODE_B, response.getCode(), "code");
        				success &= hasEtag(response);
        				success &= checkOption(new Option(etagStep3, OptionNumberRegistry.ETAG), response.getFirstOption(OptionNumberRegistry.ETAG));
                        
        				// Part C
        				request = new Request(CodeRegistry.METHOD_GET, true);
        				request.setOption(new Option(etagStep3, OptionNumberRegistry.ETAG));

    					request.setURI(uri);
    		            if (request.requiresToken()) {
    		                request.setToken(TokenManager.getInstance().acquireToken());
    		            }

    		            // enable response queue for synchronous I/O
    		            request.enableResponseQueue(true);
    		            
    	                request.execute();
    	                response = request.receiveResponse();

                        // checking the response
                        if (response != null) {
                        	
                            // print response info
                            if (verbose) {
                                System.out.println("Response received");
                                System.out.println("Time elapsed (ms): " + response.getRTT());
                                response.prettyPrint();
                            }
                        	
            				success &= checkType(Message.messageType.ACK, response.getType());
            				success &= checkInt(EXPECTED_RESPONSE_CODE_C, response.getCode(), "code");
            				success &= hasEtag(response);
            				// Option value = an arbitrary ETag value which differs from the ETag sent in step 3
            				success &= checkDifferentOption(new Option(etagStep3, OptionNumberRegistry.ETAG), response.getFirstOption(OptionNumberRegistry.ETAG));
                        }
                    }
                }
                
                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

		protected boolean checkResponse(Request request, Response response) {
			return false;
		}

	}
    
    /**
     * TD_COAP_CORE_22:
     * Perform GET transaction with responses containing the ETag option and requests containing the If-Match option (CON mode)
     * 
     * @author Matthias Kovatsch
     */
    public class CC22 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE_PREAMBLE = CodeRegistry.RESP_CONTENT;
        public static final int EXPECTED_RESPONSE_CODE_A = CodeRegistry.RESP_CHANGED;
        public static final int EXPECTED_RESPONSE_CODE_B = CodeRegistry.RESP_PRECONDITION_FAILED;
        
        public byte[] etagStep3;
        public byte[] etagStep6;

        public CC22(String serverURI) {
            super(CC22.class.getSimpleName());

            Request request = new Request(CodeRegistry.METHOD_GET, true);
            executeRequest(request, serverURI, RESOURCE_URI);
            
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                // Part A
                request.execute();
                response = request.receiveResponse();
                
                // checking the response
                if (response != null) {
                	
                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): " + response.getRTT());
                        response.prettyPrint();
                    }
                	
                    success &= checkType(Message.messageType.ACK, response.getType());
    				success &= checkInt(EXPECTED_RESPONSE_CODE_PREAMBLE, response.getCode(), "code");
    				success &= hasEtag(response);
    				etagStep3 = response.getFirstOption(OptionNumberRegistry.ETAG).getRawValue();
					
					// Part A
					request = new Request(CodeRegistry.METHOD_PUT, true);
		            request.setOption(new Option(etagStep3, OptionNumberRegistry.IF_MATCH));
		            request.setPayload("TD_COAP_CORE_22 Part A", MediaTypeRegistry.TEXT_PLAIN);

					request.setURI(uri);
		            if (request.requiresToken()) {
		                request.setToken(TokenManager.getInstance().acquireToken());
		            }

		            // enable response queue for synchronous I/O
		            request.enableResponseQueue(true);
		            
	                request.execute();
	                response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                    	
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }
                    	
                        success &= checkType(Message.messageType.ACK, response.getType());
        				success &= checkInt(EXPECTED_RESPONSE_CODE_A, response.getCode(), "code");
        				success &= hasEtag(response);
        				// Option value = an arbitrary ETag value which differs from the ETag sent in step 3
        				success &= checkDifferentOption(new Option(etagStep3, OptionNumberRegistry.ETAG), response.getFirstOption(OptionNumberRegistry.ETAG));
        				etagStep6 = response.getFirstOption(OptionNumberRegistry.ETAG).getRawValue();
                        
        				// Part B
        				request = new Request(CodeRegistry.METHOD_PUT, true);
        	            request.setOption(new Option(etagStep6, OptionNumberRegistry.IF_MATCH));
        	            request.setPayload("TD_COAP_CORE_22 Part B", MediaTypeRegistry.TEXT_PLAIN);

    					request.setURI(uri);
    		            if (request.requiresToken()) {
    		                request.setToken(TokenManager.getInstance().acquireToken());
    		            }

    		            // enable response queue for synchronous I/O
    		            request.enableResponseQueue(true);
    		            
    	                request.execute();
    	                response = request.receiveResponse();

                        // checking the response
                        if (response != null) {
                        	
                            // print response info
                            if (verbose) {
                                System.out.println("Response received");
                                System.out.println("Time elapsed (ms): " + response.getRTT());
                                response.prettyPrint();
                            }
                        	
                            success &= checkType(Message.messageType.ACK, response.getType());
            				success &= checkInt(EXPECTED_RESPONSE_CODE_B, response.getCode(), "code");
                        }
                    }
                }
                
                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
        	return false;
        }
    }
    
    /**
     * TD_COAP_CORE_23:
     * Perform GET transaction with responses containing the ETag option and requests containing the If-None-Match option (CON mode)
     * 
     * @author Matthias Kovatsch
     */
    public class CC23 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE_A = CodeRegistry.RESP_CREATED;
        public static final int EXPECTED_RESPONSE_CODE_B = CodeRegistry.RESP_PRECONDITION_FAILED;

        public CC23(String serverURI) {
            super(CC23.class.getSimpleName());

            Request request = new Request(CodeRegistry.METHOD_PUT, true);
            request.setIfNoneMatch();
            request.setPayload("TD_COAP_CORE_23 Part A", MediaTypeRegistry.TEXT_PLAIN);
            executeRequest(request, serverURI, RESOURCE_URI);
            
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                // Part A
                request.execute();
                response = request.receiveResponse();
                
                // checking the response
                if (response != null) {
                	
                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): " + response.getRTT());
                        response.prettyPrint();
                    }
                	
                    success &= checkType(Message.messageType.ACK, response.getType());
    				success &= checkInt(EXPECTED_RESPONSE_CODE_A, response.getCode(), "code");
					
					// Part B
    				request = new Request(CodeRegistry.METHOD_PUT, true);
    				request.setIfNoneMatch();
    	            request.setPayload("TD_COAP_CORE_23 Part B", MediaTypeRegistry.TEXT_PLAIN);

					request.setURI(uri);
		            if (request.requiresToken()) {
		                request.setToken(TokenManager.getInstance().acquireToken());
		            }

		            // enable response queue for synchronous I/O
		            request.enableResponseQueue(true);
		            
	                request.execute();
	                response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                    	
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }
                    	
                        success &= checkType(Message.messageType.ACK, response.getType());
        				success &= checkInt(EXPECTED_RESPONSE_CODE_B, response.getCode(), "code");
                        
                    }
                }
                
                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
        	return false;
        }
    }
    
    /**
     * TD_COAP_CORE_24:
     * Perform POST transaction with responses containing several Location-Path options (Reverse Proxy in CON mode)
     * 
     * @author Matthias Kovatsch
     */
    public class CC24 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CREATED;

        public CC24(String serverURI) {
            super(CC24.class.getSimpleName());
            
            // create the request
            Request request = new Request(CodeRegistry.METHOD_POST, true);
            // add payload
            request.setPayload("TD_COAP_CORE_24", MediaTypeRegistry.TEXT_PLAIN);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            
            List<Option> options = response.getOptions(OptionNumberRegistry.LOCATION_PATH);
            success &= checkOption(new Option("location1", OptionNumberRegistry.LOCATION_PATH), options.get(0));
            success &= checkOption(new Option("location2", OptionNumberRegistry.LOCATION_PATH), options.get(1));
            success &= checkOption(new Option("location3", OptionNumberRegistry.LOCATION_PATH), options.get(2));
            
            // TODO Client interface returns the response
            // •	2.01 created
            // •	Location: coap://proxy/location1/location2/location3


            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_25:
     * Perform POST transaction with  responses containing several Location- Query  option (Reverse proxy)
     * 
     * @author Matthias Kovatsch
     */
    public class CC25 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/location-query";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CREATED;

		public CC25(String serverURI) {
			super(CC25.class.getSimpleName());

			// create the request
            Request request = new Request(CodeRegistry.METHOD_POST, true);
            // add payload
            request.setPayload("TD_COAP_CORE_25", MediaTypeRegistry.TEXT_PLAIN);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
		}

        protected boolean checkResponse(Request request, Response response) {
        	boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasLocationQuery(response);
            
            List<Option> options = response.getOptions(OptionNumberRegistry.LOCATION_QUERY);
            success &= checkOption(new Option("first=1", OptionNumberRegistry.LOCATION_QUERY), options.get(0));
            success &= checkOption(new Option("second=2", OptionNumberRegistry.LOCATION_QUERY), options.get(1));

            return success;
        }
    }
    
    /**
     * TD_COAP_CORE_26:
     * Perform GET transaction containing the Accept option (CON mode
     * 
     * @author Matthias Kovatsch
     */
    public class CC26 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/multi-format";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CC26(String serverURI) {
            super(CC26.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            request.setOption(new Option(MediaTypeRegistry.TEXT_PLAIN, OptionNumberRegistry.ACCEPT));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                // Part A
                request.execute();
                response = request.receiveResponse();
                
                // checking the response
                if (response != null) {
                	
                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): " + response.getRTT());
                        response.prettyPrint();
                    }
                	
                    success &= checkType(Message.messageType.ACK, response.getType());
    	            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
    				success &= checkOption(new Option(MediaTypeRegistry.TEXT_PLAIN, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
					
					// Part B
    				request = new Request(CodeRegistry.METHOD_GET, true);
    	            request.setOption(new Option(MediaTypeRegistry.APPLICATION_XML, OptionNumberRegistry.ACCEPT));

					request.setURI(uri);
		            if (request.requiresToken()) {
		                request.setToken(TokenManager.getInstance().acquireToken());
		            }

		            // enable response queue for synchronous I/O
		            request.enableResponseQueue(true);
		            
	                request.execute();
	                response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                    	
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }
                    	
                        success &= checkType(Message.messageType.ACK, response.getType());
        	            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
        				success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_XML, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
                        
                    }
                }
                
                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
			return false;
        }
    }
    
    /**
     * TD_COAP_CORE_27:
     * Perform GET transaction with responses containing the ETag option and requests containing the If-Match option (CON mode)
     * 
     * @author Matthias Kovatsch
     */
    public class CC27 extends TestClientAbstract {

    	public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE_PREAMBLE = CodeRegistry.RESP_CONTENT;
        public static final int EXPECTED_RESPONSE_CODE_A = CodeRegistry.RESP_CHANGED;
        public static final int EXPECTED_RESPONSE_CODE_B = CodeRegistry.RESP_PRECONDITION_FAILED;
        
        public byte[] etagStep4;
        public byte[] etagStep9;

        public CC27(String serverURI) {
            super(CC27.class.getSimpleName());

            Request request = new Request(CodeRegistry.METHOD_GET, true);
            executeRequest(request, serverURI, RESOURCE_URI);
            
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                // Part Preamble
                request.execute();
                response = request.receiveResponse();
                
                // checking the response
                if (response != null) {
                	
                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): " + response.getRTT());
                        response.prettyPrint();
                    }
                	
                    success &= checkType(Message.messageType.ACK, response.getType());
    				success &= checkInt(EXPECTED_RESPONSE_CODE_PREAMBLE, response.getCode(), "code");
    				success &= hasEtag(response);
    				etagStep4 = response.getFirstOption(OptionNumberRegistry.ETAG).getRawValue();
					
					// Part A
					request = new Request(CodeRegistry.METHOD_PUT, true);
		            request.setOption(new Option(etagStep4, OptionNumberRegistry.IF_MATCH));
		            request.setPayload("TD_COAP_CORE_27 Part A", MediaTypeRegistry.TEXT_PLAIN);

					request.setURI(uri);
		            if (request.requiresToken()) {
		                request.setToken(TokenManager.getInstance().acquireToken());
		            }

		            // enable response queue for synchronous I/O
		            request.enableResponseQueue(true);
		            
	                request.execute();
	                response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                    	
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }
                    	
                        success &= checkType(Message.messageType.ACK, response.getType());
        				success &= checkInt(EXPECTED_RESPONSE_CODE_A, response.getCode(), "code");
        				success &= hasEtag(response);
        				// Option value = an arbitrary ETag value which differs from the ETag sent in step 4
        				success &= checkDifferentOption(new Option(etagStep4, OptionNumberRegistry.ETAG), response.getFirstOption(OptionNumberRegistry.ETAG));
        				etagStep9 = response.getFirstOption(OptionNumberRegistry.ETAG).getRawValue();
                        
        				// Part B
        				request = new Request(CodeRegistry.METHOD_PUT, true);
        	            request.setOption(new Option(etagStep9, OptionNumberRegistry.IF_MATCH));
        	            request.setPayload("TD_COAP_CORE_27 Part B", MediaTypeRegistry.TEXT_PLAIN);

    					request.setURI(uri);
    		            if (request.requiresToken()) {
    		                request.setToken(TokenManager.getInstance().acquireToken());
    		            }

    		            // enable response queue for synchronous I/O
    		            request.enableResponseQueue(true);
    		            
    	                request.execute();
    	                response = request.receiveResponse();

                        // checking the response
                        if (response != null) {
                        	
                            // print response info
                            if (verbose) {
                                System.out.println("Response received");
                                System.out.println("Time elapsed (ms): " + response.getRTT());
                                response.prettyPrint();
                            }
                        	
                            success &= checkType(Message.messageType.ACK, response.getType());
            				success &= checkInt(EXPECTED_RESPONSE_CODE_B, response.getCode(), "code");
                        }
                    }
                }
                
                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
        	return false;
        }
    }
    
    /**
     * TD_COAP_CORE_28:
     * Perform GET transaction with responses containing the ETag option and requests containing the If-None-Match option (CON mode) (Reverse proxy)
     * 
     * @author Matthias Kovatsch
     */
    public class CC28 extends TestClientAbstract {

    	public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE_A = CodeRegistry.RESP_CREATED;
        public static final int EXPECTED_RESPONSE_CODE_B = CodeRegistry.RESP_PRECONDITION_FAILED;

        public CC28(String serverURI) {
            super(CC28.class.getSimpleName());

            Request request = new Request(CodeRegistry.METHOD_PUT, true);
            request.setIfNoneMatch();
            request.setPayload("TD_COAP_CORE_28 Part A", MediaTypeRegistry.TEXT_PLAIN);
            executeRequest(request, serverURI, RESOURCE_URI);
            
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                // Part A
                request.execute();
                response = request.receiveResponse();
                
                // checking the response
                if (response != null) {
                	
                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): " + response.getRTT());
                        response.prettyPrint();
                    }
                	
                    success &= checkType(Message.messageType.ACK, response.getType());
    				success &= checkInt(EXPECTED_RESPONSE_CODE_A, response.getCode(), "code");
					
					// Part B
    				request = new Request(CodeRegistry.METHOD_PUT, true);
    				request.setIfNoneMatch();
    	            request.setPayload("TD_COAP_CORE_23 Part B", MediaTypeRegistry.TEXT_PLAIN);

					request.setURI(uri);
		            if (request.requiresToken()) {
		                request.setToken(TokenManager.getInstance().acquireToken());
		            }

		            // enable response queue for synchronous I/O
		            request.enableResponseQueue(true);
		            
	                request.execute();
	                response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                    	
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }
                    	
                        success &= checkType(Message.messageType.ACK, response.getType());
        				success &= checkInt(EXPECTED_RESPONSE_CODE_B, response.getCode(), "code");
                        
                    }
                }
                
                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
        	return false;
        }
    }
    
    /**
     * TD_COAP_CORE_29:
     * Perform GET transaction with responses containing the Max-Age option (Reverse proxy)
     * 
     * @author Matthias Kovatsch
     */
    public class CC29 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/test";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        
        private String expectedPayload;

        public CC29(String serverURI) {
            super(CC29.class.getSimpleName());

            Request request = new Request(CodeRegistry.METHOD_GET, true);
            executeRequest(request, serverURI, RESOURCE_URI);
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                request.execute();
                response = request.receiveResponse();
                
                // checking the response
                if (response != null) {
                	
                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): " + response.getRTT());
                        response.prettyPrint();
                    }
                	
                    success &= checkType(Message.messageType.ACK, response.getType());
    				success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
    				success &= hasEtag(response);
    				success &= hasMaxAge(response);
    				expectedPayload = response.getPayloadString();
    				
    				// A confirmable GET request is sent to proxy from Client before Max-Age expires
    				request = new Request(CodeRegistry.METHOD_GET, true);

					request.setURI(uri);
		            if (request.requiresToken()) {
		                request.setToken(TokenManager.getInstance().acquireToken());
		            }

		            // enable response queue for synchronous I/O
		            request.enableResponseQueue(true);
		            
	                request.execute();
	                response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                    	
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }
                    	
                        success &= checkType(Message.messageType.ACK, response.getType());
        				success &= hasMaxAge(response);
        				success &= checkString(expectedPayload, response.getPayloadString(), "Payload cached");
                        
                    }
                }
                
                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
            return false;
        }
    }
   

    /**
     * TD_COAP_LINK_01:
     * Access to well-known interface for resource discovery.
     * 
     * @author Matthias Kovatsch
     */
    public class CL01 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/.well-known/core";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CL01(String serverURI) {
            super(CL01.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
            
            return success;
        }
    }

    /**
     * TD_COAP_LINK_02:
     * Use filtered requests for limiting discovery results.
     * 
     * @author Matthias Kovatsch
     */
    public class CL02 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/.well-known/core";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final String EXPECTED_RT = "rt=Type1";

        public CL02(String serverURI) {
            super(CL02.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set query
            request.setOption(new Option(EXPECTED_RT, OptionNumberRegistry.URI_QUERY));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
            success &= checkDiscovery(EXPECTED_RT, response.getPayloadString());

            return success;
        }
    }
    
    /**
     * TD_COAP_LINK_03:
     * Handle empty prefix value strings
     * 
     * @author Matthias Kovatsch
     */
    public class CL03 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/.well-known/core";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final String EXPECTED_RT = "rt=*";

        public CL03(String serverURI) {
            super(CL03.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set query
            request.setOption(new Option(EXPECTED_RT, OptionNumberRegistry.URI_QUERY));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
            success &= checkDiscovery(EXPECTED_RT, response.getPayloadString());

            return success;
        }
    }
    
    /**
     * TD_COAP_LINK_04:
     * Handle empty prefix value strings
     * 
     * @author Matthias Kovatsch
     */
    public class CL04 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/.well-known/core";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final String EXPECTED_RT = "rt=Type2";

        public CL04(String serverURI) {
            super(CL04.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set query
            request.setOption(new Option(EXPECTED_RT, OptionNumberRegistry.URI_QUERY));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
            success &= checkDiscovery(EXPECTED_RT, response.getPayloadString());

            return success;
        }
    }
    
    /**
     * TD_COAP_LINK_05:
     * Filter discovery results using if attribute and prefix value strings
     * 
     * @author Matthias Kovatsch
     */
    public class CL05 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/.well-known/core";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final String EXPECTED_IF = "if=If*";

        public CL05(String serverURI) {
            super(CL05.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set query
            request.setOption(new Option(EXPECTED_IF, OptionNumberRegistry.URI_QUERY));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
            success &= checkDiscovery(EXPECTED_IF, response.getPayloadString());

            return success;
        }
    }
    
    /**
     * TD_COAP_LINK_06:
     * Filter discovery results using sz attribute and prefix value strings
     * 
     * @author Matthias Kovatsch
     */
    public class CL06 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/.well-known/core";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final String EXPECTED_SZ = "sz=*";

        public CL06(String serverURI) {
            super(CL06.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set query
            request.setOption(new Option(EXPECTED_SZ, OptionNumberRegistry.URI_QUERY));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
            success &= checkDiscovery(EXPECTED_SZ, response.getPayloadString());

            return success;
        }
    }
    
    /**
     * TD_COAP_LINK_07:
     * Filter discovery results using href attribute and complete value strings
     * 
     * @author Matthias Kovatsch
     */
    public class CL07 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/.well-known/core";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final String EXPECTED_HREF = "href=/link1";

        public CL07(String serverURI) {
            super(CL07.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set query
            request.setOption(new Option(EXPECTED_HREF, OptionNumberRegistry.URI_QUERY));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
            success &= checkDiscovery(EXPECTED_HREF, response.getPayloadString());

            return success;
        }
    }
    
    /**
     * TD_COAP_LINK_08:
     * Filter discovery results using href attribute and complete value strings
     * 
     * @author Matthias Kovatsch
     */
    public class CL08 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/.well-known/core";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final String EXPECTED_HREF = "href=/link*";

        public CL08(String serverURI) {
            super(CL08.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set query
            request.setOption(new Option(EXPECTED_HREF, OptionNumberRegistry.URI_QUERY));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
            success &= checkDiscovery(EXPECTED_HREF, response.getPayloadString());

            return success;
        }
    }
    
    /**
     * TD_COAP_LINK_09:
     * Arrange link descriptions hierarchically
     * 
     * @author Matthias Kovatsch
     */
    public class CL09 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/.well-known/core";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final String RESOURCE_URI_2 = "/path";
        public static final String RESOURCE_URI_3 = "/path/sub1";
        public static final String URI_QUERY = "ct=40";

        public CL09(String serverURI) {
            super(CL09.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            request.setOption(new Option(URI_QUERY, OptionNumberRegistry.URI_QUERY));
            executeRequest(request, serverURI, RESOURCE_URI);
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                request.execute();
                response = request.receiveResponse();
                
                // checking the response
                if (response != null) {
                	
                    // print response info
                    if (verbose) {
                        System.out.println("Response received");
                        System.out.println("Time elapsed (ms): " + response.getRTT());
                        response.prettyPrint();
                    }
                	
                    success &= checkType(Message.messageType.ACK, response.getType());
                    success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
                    success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
    				
    				// Client sends a GET request for /path to Server
    				request = new Request(CodeRegistry.METHOD_GET, true);
    				try {
    	                uri = new URI(serverURI + RESOURCE_URI_2);
    	            } catch (URISyntaxException use) {
    	                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
    	            }

					request.setURI(uri);
		            if (request.requiresToken()) {
		                request.setToken(TokenManager.getInstance().acquireToken());
		            }

		            // enable response queue for synchronous I/O
		            request.enableResponseQueue(true);
		            
	                request.execute();
	                response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                    	
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
							System.out.println("Time elapsed (ms): " + response.getRTT());
							response.prettyPrint();
						}

						success &= checkType(Message.messageType.ACK, response.getType());
						success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
						success &= checkOption(new Option(MediaTypeRegistry.APPLICATION_LINK_FORMAT, OptionNumberRegistry.CONTENT_TYPE), response.getFirstOption(OptionNumberRegistry.CONTENT_TYPE));
						
						// Client sends a GET request for /path/sub1
						request = new Request(CodeRegistry.METHOD_GET, true);
						try {
	    	                uri = new URI(serverURI + RESOURCE_URI_3);
	    	            } catch (URISyntaxException use) {
	    	                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
	    	            }
	    				
	    				request.setURI(uri);
			            if (request.requiresToken()) {
			                request.setToken(TokenManager.getInstance().acquireToken());
			            }

			            // enable response queue for synchronous I/O
			            request.enableResponseQueue(true);
			            
		                request.execute();
		                response = request.receiveResponse();

	                    // checking the response
	                    if (response != null) {
	                    	
	                        // print response info
	                        if (verbose) {
	                            System.out.println("Response received");
								System.out.println("Time elapsed (ms): " + response.getRTT());
								response.prettyPrint();
							}

							success &= checkType(Message.messageType.ACK, response.getType());
							success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
						}
					}
                }
                
                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
           return false;
        }
    }

    /**
     * TD_COAP_BLOCK_01:
     * Handle GET blockwise transfer for large resource (early negotiation).
     * 
     * @author Matthias Kovatsch
     */
    public class CB01 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/large";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CB01(String serverURI) {
            super(CB01.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set block2
            request.setOption(new BlockOption(OptionNumberRegistry.BLOCK2, 0, BlockOption.encodeSZX(PLUGTEST_BLOCK_SIZE), false));
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

		protected boolean checkResponse(Request request, Response response) {
			boolean success = response.hasOption(OptionNumberRegistry.BLOCK2);
			
            
			if (!success) {
				System.out.println("FAIL: no Block2 option");
			} else {
            // get actual number of blocks for check
            int maxNUM = ((BlockOption)response.getFirstOption(OptionNumberRegistry.BLOCK2)).getNUM();

            success &= checkType(Message.messageType.ACK, response.getType());
            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= checkOption(
                                   new BlockOption(OptionNumberRegistry.BLOCK2, maxNUM, BlockOption.encodeSZX(PLUGTEST_BLOCK_SIZE), false),
                                   response.getFirstOption(OptionNumberRegistry.BLOCK2)
                                  );
            success &= hasContentType(response);
			}
            return success;
        }
    }
    
    /**
     * TD_COAP_BLOCK_02:
     * Handle GET blockwise transfer for large resource (late negotiation).
     * 
     * @author Matthias Kovatsch
     */
    public class CB02 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/large";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CB02(String serverURI) {
            super(CB02.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = response.hasOption(OptionNumberRegistry.BLOCK2);
            
            if (!success) {
                System.out.println("FAIL: no Block2 option");
            } else {
                // get actual number of blocks for check
                int maxNUM = ((BlockOption)response.getFirstOption(OptionNumberRegistry.BLOCK2)).getNUM();
    
                success &= checkType(Message.messageType.ACK, response.getType());
                success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
                success &= checkOption(
                                       new BlockOption(OptionNumberRegistry.BLOCK2, maxNUM, BlockOption.encodeSZX(PLUGTEST_BLOCK_SIZE), false),
                                       response.getFirstOption(OptionNumberRegistry.BLOCK2)
                                      );
                success &= hasContentType(response);
            }
            return success;
        }
    }

    /**
     * TD_COAP_BLOCK_03:
     * Handle PUT blockwise transfer for large resource.
     * 
     * @author Matthias Kovatsch
     */
    public class CB03 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/large-update";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CHANGED;

        public CB03(String serverURI) {
            super(CB03.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_PUT, true);
            
            // create payload
            StringBuilder builder = new StringBuilder();
            for (int i=0; i<20; ++i) {
                for (int j=0; j<63; ++j) {
                    builder.append(Integer.toString(i%10));
                }
                builder.append('\n');
            }
            request.setPayload(builder.toString(), MediaTypeRegistry.TEXT_PLAIN);
            
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = response.hasOption(OptionNumberRegistry.BLOCK1);
            
            if (!success) {
                System.out.println("FAIL: no Block1 option");
            } else {
                // get actual number of blocks for check
                int maxNUM = ((BlockOption)response.getFirstOption(OptionNumberRegistry.BLOCK1)).getNUM();
    
                success &= checkType(Message.messageType.ACK, response.getType());
                success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
                success &= checkOption(
                                       new BlockOption(OptionNumberRegistry.BLOCK1, maxNUM, BlockOption.encodeSZX(PLUGTEST_BLOCK_SIZE), false),
                                       response.getFirstOption(OptionNumberRegistry.BLOCK1)
                                      );
            }

            return success;
        }
    }

    /**
     * TD_COAP_BLOCK_04:
     * Handle POST blockwise transfer for large resource.
     * 
     * @author Matthias Kovatsch
     */
    public class CB04 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/large-create";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CREATED;

        public CB04(String serverURI) {
            super(CB04.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_POST, true);
            
            // create payload
            StringBuilder builder = new StringBuilder();
            for (int i=0; i<20; ++i) {
                for (int j=0; j<63; ++j) {
                    builder.append(Integer.toString(i%10));
                }
                builder.append('\n');
            }
            request.setPayload(builder.toString(), MediaTypeRegistry.TEXT_PLAIN);
            
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = response.hasOption(OptionNumberRegistry.BLOCK1);
            
            if (!success) {
                System.out.println("FAIL: no Block1 option");
            } else {
                // get actual number of blocks for check
                int maxNUM = ((BlockOption)response.getFirstOption(OptionNumberRegistry.BLOCK1)).getNUM();
    
                success &= checkType(Message.messageType.ACK, response.getType());
                success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
                success &= checkOption(
                                       new BlockOption(OptionNumberRegistry.BLOCK1, maxNUM, BlockOption.encodeSZX(PLUGTEST_BLOCK_SIZE), false),
                                       response.getFirstOption(OptionNumberRegistry.BLOCK1)
                                      );
                success &= hasLocation(response);
            }

            return success;
        }
    }

    /**
     * TD_COAP_OBS_01:
     * Handle resource observation with CON messages
     * TD_COAP_OBS_03:
     * Stop resource observation.
     * 
     * @author Matthias Kovatsch
     */
    public class CO01_03 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/obs";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CO01_03(String serverURI) {
            super(CO01_03.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set Observe option
            request.setObserve();
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasObserve(response);
            success &= hasToken(response);
            success &= hasContentType(response);

            return success;
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);
            
            // for observing
            int observeLoop = 5;

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                request.execute();
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                    
                // receive multiple responses
				for (int l = 0; l < observeLoop; ++l) {
                    response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                        
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }

                        success &= checkResponse(response.getRequest(), response);
                        
                        if (!hasObserve(response)) {
                            break;
                        }
                    }
                }
                
                // TD_COAP_OBS_03: Stop resource observation
                request.removeOptions(OptionNumberRegistry.OBSERVE);
                request.setMID(-1);
                request.execute();
                response = request.receiveResponse();

                success &= hasObserve(response, true);

                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }
    }
    
    /**
     * TD_COAP_OBS_02:
     * Handle resource observation with NON messages
     * 
     * @author Matthias Kovatsch
     */
    public class CO02 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/obs";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CO02(String serverURI) {
            super(CO02.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, false);
            // set Observe option
            request.setObserve();
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasObserve(response);
            success &= hasToken(response);
            success &= hasContentType(response);

            return success;
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);
            
            // for observing
            int observeLoop = 5;

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                request.execute();
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                    
                // receive multiple responses
				for (int l = 0; l < observeLoop; ++l) {
                    response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                        
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }

                        success &= checkResponse(response.getRequest(), response);
                        
                        if (!hasObserve(response)) {
                            break;
                        }
                    }
                }
                
                // TD_COAP_OBS_03: Stop resource observation
                request.removeOptions(OptionNumberRegistry.OBSERVE);
                request.setMID(-1);
                request.execute();
                response = request.receiveResponse();

                success &= hasObserve(response, true);

                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }
    }
    
    /**
     * TD_COAP_OBS_04:
     * Client detection of deregistration (Max-Age).
     * TD_COAP_OBS_06:
     * Server detection of deregistration (explicit RST).
     * 
     * @author Matthias Kovatsch
     */
    public class CO04_06 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/obs";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        private Timer timer = new Timer(true);

        /*
         * Utility class to provide transaction timeouts
         */
        private class MaxAgeTask extends TimerTask {
            
            private Request request;

            public MaxAgeTask(Request request) {
                this.request = request;
            }
            
            @Override
            public void run() {
                this.request.handleTimeout();
            }
        }

        public CO04_06(String serverURI) {
            super(CO04_06.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set Observe option
            request.setObserve();
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasObserve(response);
            success &= hasContentType(response);

            return success;
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            if (sync) {
                request.enableResponseQueue(true);
            }
            
            // for observing
            int observeLoop = 5;

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                boolean timedOut = false;
                
                MaxAgeTask timeout = null;
                
                request.execute();
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                
                for (int l=0; l<observeLoop; ++l) {
                    
                    response = request.receiveResponse();
                    
                    // checking the response
                    if (response != null) {
                        
                        if (l>=2 && !timedOut) {
                            System.out.println("+++++++++++++++++++++++");
                            System.out.println("++++ REBOOT SERVER ++++");
                            System.out.println("+++++++++++++++++++++++");
                        }
                        
                        if (timeout!=null) {
                            timeout.cancel();
                            timer.purge();
                        }
                        
                        long time = response.getMaxAge()*1000;

                        timeout = new MaxAgeTask(request);
                        timer.schedule(timeout, time+1000);
                        
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }

                        success &= checkResponse(response.getRequest(), response);
                        
                        if (!hasObserve(response)) {
                            break;
                        }
                        
                    } else {
                        timedOut = true;
                        System.out.println("PASS: Max-Age timed out");
                        request.setMID(-1);
                        request.execute();
                        
                        ++observeLoop;
                    }
                }
                
                // RST to cancel
                response.reject();
                
                success &= timedOut;

                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }
    }

    /**
     * TD_COAP_OBS_05:
     * Server detection of deregistration (client OFF).
     * 
     * @author Matthias Kovatsch
     */
    public class CO05 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/obs";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;

        public CO05(String serverURI) {
            super(CO05.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            // set Observe option
            request.setObserve();
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
            
            // TODO switch off client
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasObserve(response);
            success &= hasContentType(response);

            return success;
        }
    }
    
    /**
     * TD_COAP_OBS_07:
     * Server cleans the observers list on DELETE
     * 
     * @author Matthias Kovatsch
     */
    public class CO07 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/obs";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final int EXPECTED_RESPONSE_CODE_1 = CodeRegistry.RESP_DELETED;
        public static final int EXPECTED_RESPONSE_CODE_2 = CodeRegistry.RESP_NOT_FOUND;

        public CO07(String serverURI) {
            super(CO07.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            request.setToken(TokenManager.getInstance().acquireToken(false));
            request.setObserve();
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
            
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);
            
            // for observing
            int observeLoop = 2;

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                request.execute();
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                    
                // receive multiple responses
				for (int l = 0; l < observeLoop; ++l) {
                    response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                        
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }

                        success &= checkResponse(response.getRequest(), response);
                        
                        if (!hasObserve(response)) {
                            break;
                        }
                    }
                }
                
                // Client is requested to send to the server a DELETE request with observe option for resource /obs
                Request asyncRequest = new Request(CodeRegistry.METHOD_DELETE, true);
                asyncRequest.setObserve();
                
                asyncRequest.setURI(uri);
                if (asyncRequest.requiresToken()) {
                	asyncRequest.setToken(TokenManager.getInstance().acquireToken());
                }

                // enable response queue for synchronous I/O
                asyncRequest.enableResponseQueue(true);
                asyncRequest.execute();
                
                response = asyncRequest.receiveResponse();

                // checking the response
                if (response != null) {
                	success &= checkInt(EXPECTED_RESPONSE_CODE_1, response.getCode(), "code");
                }
                // TODO
                // Server sends a notification containing:
                // •	Type = 0 (CON)
                // •	Code = 132 (4.04 NOT FOUND)
                // •	Token value = same as one found in the step 2
                // •	Observe option indicating increasing values

                response = request.receiveResponse();
                if (response != null) {
                	success &= checkInt(EXPECTED_RESPONSE_CODE_2, response.getCode(), "code");
                }

                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasObserve(response);
            success &= hasContentType(response);

            return success;
        }
    }
    
    /**
     * TD_COAP_OBS_08:
     * Server cleans the observers list when observed resource content-format changes
     * 
     * @author Matthias Kovatsch
     */
    public class CO08 extends TestClientAbstract {

        public static final String RESOURCE_URI = "/obs";
        public static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        public static final int EXPECTED_RESPONSE_CODE_1 = CodeRegistry.RESP_CHANGED;
        public static final int EXPECTED_RESPONSE_CODE_2 = CodeRegistry.RESP_INTERNAL_SERVER_ERROR;

        public CO08(String serverURI) {
            super(CO08.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            request.setToken(TokenManager.getInstance().acquireToken(false));
            request.setObserve();
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
            
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);
            
            // for observing
            int observeLoop = 2;

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                request.execute();
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                    
                // receive multiple responses
				for (int l = 0; l < observeLoop; ++l) {
                    response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                        
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }

                        success &= checkResponse(response.getRequest(), response);
                        
                        if (!hasObserve(response)) {
                            break;
                        }
                    }
                }
                
                // Client is requested to update the /obs content-format on Server
                Request asyncRequest = new Request(CodeRegistry.METHOD_POST, true);
                asyncRequest.setContentType(MediaTypeRegistry.APPLICATION_XML);
                asyncRequest.setURI(uri);
                if (asyncRequest.requiresToken()) {
                	asyncRequest.setToken(TokenManager.getInstance().acquireToken());
                }

                // enable response queue for synchronous I/O
                asyncRequest.enableResponseQueue(true);
                asyncRequest.execute();
                
                response = asyncRequest.receiveResponse();

                // checking the response
                if (response != null) {
                	success &= checkInt(EXPECTED_RESPONSE_CODE_1, response.getCode(), "code");
                }
                // TODO
                // Server sends notification containing:
                // •	Type = 0 (CON)
                // •	Code = 160 (5.00 INTERNAL SERVER ERROR)
                // •	Token value = same as one found in the step 2
                // •	Observe option indicating increasing values

                response = request.receiveResponse();
                if (response != null) {
                	success &= checkInt(EXPECTED_RESPONSE_CODE_2, response.getCode(), "code");
                	success &= hasToken(response);
                	success &= hasObserve(response);
                }

                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasObserve(response);
            success &= hasContentType(response);

            return success;
        }
    }
    
    /**
     * TD_COAP_OBS_09:
     * Update of the observed resource
     * 
     * @author Matthias Kovatsch
     */
    public class CO09 extends TestClientAbstract {

    	private static final String RESOURCE_URI = "/obs";
        private static final int EXPECTED_RESPONSE_CODE = CodeRegistry.RESP_CONTENT;
        private static final int EXPECTED_RESPONSE_CODE_1 = CodeRegistry.RESP_CHANGED;
        
        private int contentType = MediaTypeRegistry.TEXT_PLAIN;
        private String newValue = "New value";

        public CO09(String serverURI) {
            super(CO09.class.getSimpleName());

            // create the request
            Request request = new Request(CodeRegistry.METHOD_GET, true);
            request.setToken(TokenManager.getInstance().acquireToken(false));
            request.setObserve();
            // set the parameters and execute the request
            executeRequest(request, serverURI, RESOURCE_URI);
            
        }
        
        @Override
        protected synchronized void executeRequest(Request request, String serverURI, String resourceUri) {
            if (serverURI == null || serverURI.isEmpty()) {
                throw new IllegalArgumentException("serverURI == null || serverURI.isEmpty()");
            }
            
            // defensive check for slash
            if (!serverURI.endsWith("/") && !resourceUri.startsWith("/")) {
                resourceUri = "/" + resourceUri;
            }

            URI uri = null;
            try {
                uri = new URI(serverURI + resourceUri);
            } catch (URISyntaxException use) {
                throw new IllegalArgumentException("Invalid URI: " + use.getMessage());
            }

            request.setURI(uri);
            if (request.requiresToken()) {
                request.setToken(TokenManager.getInstance().acquireToken());
            }

            // enable response queue for synchronous I/O
            request.enableResponseQueue(true);
            
            // for observing
            int observeLoop = 2;

            // print request info
            if (verbose) {
                System.out.println("Request for test " + this.testName + " sent");
                request.prettyPrint();
            }

            // execute the request
            try {
                Response response = null;
                boolean success = true;
                
                request.execute();
                
                System.out.println();
                System.out.println("**** TEST: " + testName + " ****");
                System.out.println("**** BEGIN CHECK ****");
                    
                // receive multiple responses
				for (int l = 0; l < observeLoop; ++l) {
                    response = request.receiveResponse();

                    // checking the response
                    if (response != null) {
                        
                        // print response info
                        if (verbose) {
                            System.out.println("Response received");
                            System.out.println("Time elapsed (ms): " + response.getRTT());
                            response.prettyPrint();
                        }

                        success &= checkResponse(response.getRequest(), response);
                        
                        if (!hasObserve(response)) {
                            break;
                        }
                    }
                }
                
                // Client is requested to update the /obs resource on Server
                Request asyncRequest = new Request(CodeRegistry.METHOD_PUT, true);
                asyncRequest.setPayload(newValue, contentType);
                asyncRequest.setURI(uri);
                if (asyncRequest.requiresToken()) {
                	asyncRequest.setToken(TokenManager.getInstance().acquireToken());
                }

                // enable response queue for synchronous I/O
                asyncRequest.enableResponseQueue(true);
                asyncRequest.execute();
                
                response = asyncRequest.receiveResponse();

                // checking the response
                if (response != null) {
                	success &= checkInt(EXPECTED_RESPONSE_CODE_1, response.getCode(), "code");
                }

                response = request.receiveResponse();
                if (response != null) {
                	success &= hasObserve(response);
                	success &= hasContentType(response);
                	success &= hasToken(response);
                	success &= checkString(newValue, response.getPayloadString(), "payload");
                }

                if (success) {
                    System.out.println("**** TEST PASSED ****");
                    addSummaryEntry(testName + ": PASSED");
                } else {
                    System.out.println("**** TEST FAILED ****");
                    addSummaryEntry(testName + ": FAILED");
                }

                tickOffTest();
                
            } catch (IOException e) {
                System.err.println("Failed to execute request: " + e.getMessage());
                System.exit(-1);
            } catch (InterruptedException e) {
                System.err.println("Interupted during receive: " + e.getMessage());
                System.exit(-1);
            }
        }

        protected boolean checkResponse(Request request, Response response) {
            boolean success = true;

            success &= checkInt(EXPECTED_RESPONSE_CODE, response.getCode(), "code");
            success &= hasObserve(response);
            success &= hasContentType(response);
            contentType = response.getContentType();

            return success;
        }
    }
}
