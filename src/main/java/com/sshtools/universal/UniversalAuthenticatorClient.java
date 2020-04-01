package com.sshtools.universal;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import com.sshtools.common.publickey.InvalidPassphraseException;
import com.sshtools.common.publickey.SshKeyPairGenerator;
import com.sshtools.common.publickey.SshKeyUtils;
import com.sshtools.common.ssh.SshException;
import com.sshtools.common.ssh.components.SshKeyPair;
import com.sshtools.common.ssh.components.SshPublicKey;
import com.sshtools.common.ssh.components.SshRsaPublicKey;

/**
 * A client for building authentication solutions that utilise the Universal Authenticator app
 * from JADAPTIVE.
 * 
 * @author Lee Painter
 *
 */
public class UniversalAuthenticatorClient {

	private ScriptEngine engine;
	private Properties properties;
	
	/**
	 * Create an unregistered instance of the client. To authenticate a client must first
	 * register with a key server and will need to call {@link registerDevice} before attempting
	 * any authentication calls.
	 */
	public UniversalAuthenticatorClient() {
		this(new Properties());
	}
	
	/**
	 * Create an unregistered instance of the client. To authenticate a client must first
	 * register with a key server and will need to call {@link registerDevice} before attempting
	 * any authentication calls.
	 */
	public UniversalAuthenticatorClient(File propertiesFile) throws IOException {
		this();
		try(InputStream in = new FileInputStream(propertiesFile)) {
			properties.load(in);
		}
	}
	
	/**
	 * Create an instance of the client with a set of previously saved properties.
	 * @param properties
	 */
	public UniversalAuthenticatorClient(Properties properties) {
		this.properties = properties;
	}
	
	/**
	 * Refresh the current registration. This will re-key the configuration and create a new
	 * authorization token.
	 * 
	 * @throws IOException
	 */
	public void refreshRegistration() throws IOException {
		
		String username = properties.getProperty("username", null);
		String deviceName = properties.getProperty("deviceName", null);
		String hostname = properties.getProperty("hostname", null);
		
		if(Objects.isNull(username) || Objects.isNull(deviceName) || Objects.isNull(hostname)) {
			throw new IOException("Cannot reauthorize as the configuration does not look to have been authorized yet");
		}
		
		register(username, deviceName, hostname, true);
	}
	
	/**
	 * Register the authentication client.
	 * 
	 * @param username
	 * @param deviceName
	 * @throws IOException
	 */
	public void register(String username, String deviceName) throws IOException {
		register(username, deviceName, "gateway.sshtools.com", true);
	}
	
	/**
	 * Register the authentication client.
	 * 
	 * @param username
	 * @param deviceName
	 * @param hostname
	 * @throws IOException
	 */
	public void register(String username, String deviceName, String hostname) throws IOException {
		register(username, deviceName, hostname, true);
	}
	
	/**
	 * Register the authentication client with the users key server.
	 * 
	 * @param username
	 * @param deviceName
	 * @param hostname
	 * @param forceOverwrite
	 * @throws IOException
	 */
	public void register(String username, String deviceName, String hostname, boolean forceOverwrite) throws IOException {
		register(username, deviceName, hostname, 443, true, forceOverwrite);
	}

	/**
	 * Register the authentication client with the users key server.
	 * @param username
	 * @param deviceName
	 * @param hostname
	 * @param port
	 * @param strictSSL
	 * @param forceOverwrite
	 * @throws IOException
	 */
	public void register(String username, String deviceName, String hostname, int port, boolean strictSSL, boolean forceOverwrite) throws IOException {
		
		SshKeyPair pair;
		try {
			pair = SshKeyPairGenerator.generateKeyPair(SshKeyPairGenerator.ECDSA, 521);
			String key = SshKeyUtils.getFormattedKey(pair.getPublicKey(), "Desktop SSH Agent");
			String authorization = properties.getProperty("authorization", "");
			byte[] newToken = pair.getPrivateKey().sign(generateToken(deviceName, username, 
					key, 
					authorization));
			
			if(!forceOverwrite) {
				if(!verifyDevice(deviceName, authorization)) {
					throw new IOException(String.format("%s is already registered", deviceName));
				}
			}
			
			properties.put("hostname", hostname);
			properties.put("port", String.valueOf(port));
			properties.put("strictSSL", String.valueOf(strictSSL));
			
			Map<String,Object> response = fetchURL("/app/api/agent/authorize", 
					new RequestParameter("version", "1"),
					new RequestParameter("previousToken", authorization),
					new RequestParameter("token", Base64.getUrlEncoder().encodeToString(newToken)),
					new RequestParameter("deviceName", deviceName),
					new RequestParameter("username", username),
					new RequestParameter("overwrite", String.valueOf(forceOverwrite)),
					new RequestParameter("key", key));
			
			if(!isSuccess(response)) {
				throw new IOException(getMessage(response));
			}
			
			String previousToken = authorization;
			authorization = (String)response.get("message");
			
			properties.put("username", username);
			
			validateAuthorization(username, key, previousToken, deviceName, authorization);
			
			properties.put("authorization", authorization);
			properties.put("deviceName", deviceName);
			properties.put("privateKey", SshKeyUtils.getFormattedKey(pair, ""));
			properties.put("publicKey", key);
			
		} catch (SshException e) {
			throw new IOException(e.getMessage(), e);
		}			
	}
	
	/**
	 * Verify this clients registration. If the registration is not valid the client
	 * cannot be used for authentication.
	 * @return
	 * @throws IOException
	 */
	public boolean verifyRegistration() throws IOException {

		String username = properties.getProperty("username");
		String token = properties.getProperty("authorization");
		
		if(Objects.isNull(username) || Objects.isNull(token)) {
			throw new IOException("Username and token not set. Has this configuration been authorized?");
		}
		
		String hostname = properties.getProperty("hostname");
		
		if(Objects.isNull(hostname)) {
			throw new IOException("Hostname not set. Has this configuration been authorized?");
		}
		

		return isSuccess(fetchURL("/app/api/agent/check", 
				new RequestParameter("username", username),
				new RequestParameter("token", token)));
	}
	 
	private boolean verifyDevice(String deviceName, String authorization) throws IOException {
		return isSuccess(fetchURL("/app/api/agent/verify/" + deviceName + "/",
				new RequestParameter("authorization", authorization)));
	}
	
	/**
	 * Save the authentication client properties to file. This file should be kept
	 * secure with owner only read/write.
	 * 
	 * @param toFile
	 * @throws IOException
	 */
	public void save(File toFile) throws IOException {

		try(OutputStream out = new FileOutputStream(toFile)) {
			properties.store(out, "Saved by universal-authenticator-api");
		}
	}
	
	/**
	 * Get the properties of this client.
	 * 
	 * @return
	 */
	public Properties getProperties() {
		Properties tmp = new Properties();
		tmp.putAll(properties);
		return tmp;
	}
	
	/**
	 * Authenticate the user. 
	 * 
	 * This will perform an authentication with the Universal Authenticator app, generating 
	 * a random payload and verifying that the response has been signed by a key on the users
	 * Universal Authenticator.
	 * @param authorizationText
	 * @return
	 * @throws IOException
	 */
	public void authenticate(String authorizationText) throws IOException {
		
		byte[] tmp = new byte[512];
		new SecureRandom().nextBytes(tmp);
		
		authenticate(tmp, authorizationText);
		
	}
	
	/**
	 * Authenticate the user. 
	 * 
	 * This will perform an authentication with the Universal Authenticator app, using
	 * the provided payload and verifying that the response has been signed by a key on the users
	 * Universal Authenticator.
	 * @param payload
	 * @param authorizationText
	 * @return
	 * @throws IOException
	 */
	public void authenticate(byte[] payload, String authorizationText) throws IOException {
		
		verifyRegistration();
		
		try {
			SshPublicKey key = getSystemKey();
			SshKeyPair pair = SshKeyUtils.getPrivateKey(properties.getProperty("privateKey"), null);
			String username = properties.getProperty("username");
			long timestamp = System.currentTimeMillis();
			String authorization = properties.getProperty("authorization");
			byte[] token = generateAuthorization(1, timestamp, authorization, username);
			byte[] sig = pair.getPrivateKey().sign(token);
			
			Map<String,Object> response = fetchURL("/app/api/agent/signPayload", 
					new RequestParameter("username", username),
					new RequestParameter("signature", Base64.getUrlEncoder().encodeToString(sig)),
					new RequestParameter("token", authorization),
					new RequestParameter("flags", String.valueOf((key instanceof SshRsaPublicKey) ? 4 : 0)),
					new RequestParameter("fingerprint", SshKeyUtils.getFingerprint(key)),
					new RequestParameter("remoteName", properties.getProperty("deviceName")),
					new RequestParameter("text", authorizationText),
					new RequestParameter("version", "1"),
					new RequestParameter("timestamp", String.valueOf(timestamp)),
					new RequestParameter("payload", Base64.getUrlEncoder().encodeToString(payload)));
			
			if(!isSuccess(response)) {
				throw new IOException(getMessage(response));
			}
			
			String signature = (String) response.get("signature");
			if(!key.verifySignature(Base64.getUrlDecoder().decode(signature), payload)) {
				throw new IOException("The signature returned from the key server was invalid!");
			}
		
		} catch(SshException | InvalidPassphraseException e) {
			throw new IOException(e.getMessage(), e);
		}
	}
	
	private String getMessage(Map<String,Object> response) {
		return (String) response.get("message");
	}
	
	private boolean isSuccess(Map<String,Object> response) {
		return (Boolean) response.get("success");
	}
	
	private SshPublicKey getSystemKey() throws IOException {
		
		Map<String,Object> response = fetchURL(
				String.format("/app/api/userPrivateKeys/systemKey/%s", properties.getProperty("username")));

		if(!isSuccess(response)) {
			throw new IOException(getMessage(response));
		}

		return SshKeyUtils.getPublicKey((String) response.get("resource"));
		
	}
	
	private void validateAuthorization(String username, String key, String previousToken, String deviceName, String authorization) throws IOException, SshException {
		
		byte[] data = generateToken(deviceName, username, key, previousToken);

		SshPublicKey k = getSystemKey();
		
		if(!k.verifySignature(Base64.getUrlDecoder().decode(authorization), data)) {
			throw new IOException("Invalid signature in authorization response");
		}
	}

	private Map<String,Object> fetchURL(String path, RequestParameter... requestParameters) throws IOException {
		
		
		try {
			String hostname = properties.getProperty("hostname", "gateway.sshtools.com");
			
			int port = Integer.parseInt(properties.getProperty("port", "443"));
			boolean strictSSL = Boolean.parseBoolean(properties.getProperty("strictSSL", "true"));
			boolean hasParameters = requestParameters.length > 0;
			
			String request = String.format("https://%s:%d%s", hostname, port, path);
			URL url = new URL(request);
			
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setInstanceFollowRedirects(true);
			conn.setUseCaches(false);
			
			if(hasParameters) {
				StringBuffer tmp = new StringBuffer();
				for(RequestParameter param : requestParameters) {
					if(tmp.length() > 0) {
						tmp.append('&');
					}
					tmp.append(URLEncoder.encode(param.getName(), "UTF-8"));
					tmp.append('=');
					tmp.append(URLEncoder.encode(param.getValue(), "UTF-8"));
				}
				
				byte[] postData = tmp.toString().getBytes(StandardCharsets.UTF_8);
				int postDataLength = postData.length;
				
				
				conn.setDoOutput(true);
				conn.setRequestMethod("POST");
				conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
				conn.setRequestProperty("Charset", "utf-8");
				conn.setRequestProperty("Content-Length", Integer.toString(postDataLength));
				
				OutputStream out = conn.getOutputStream();
				out.write(postData);
				out.flush();
			
			}
			
			InputStream in = conn.getInputStream();
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			int r;
			while((r = in.read())> -1) {
				bout.write(r);
			}
			
			String json = new String(bout.toByteArray(), "UTF-8");
			List<Object> results = new ArrayList<Object>();
			
			if(parseJSON(json, results)) {
				@SuppressWarnings({ "unchecked"})
				Map<String,Object> result = (Map<String,Object>)results.get(0);
				return result;
			}
			
			throw new IOException("Parse json failed: " + json);
		
		} catch(MalformedURLException e) {
			throw new IOException(e.getMessage(), e);
		}
	}

	private byte[] generateToken(String deviceName, String principalName, String key, String previousToken) throws IOException {
		
		StringBuffer buffer = new StringBuffer();
		buffer.append(deviceName);
		buffer.append("|");
		buffer.append(principalName);
		buffer.append("|");
		buffer.append(key);
		buffer.append("|");
		buffer.append(previousToken==null ? "" : previousToken);
		
		return buffer.toString().getBytes("UTF-8");
	}
	
	private byte[] generateAuthorization(int version, long timestamp, String token, String username) throws IOException {
		
		StringBuffer buffer = new StringBuffer();
		buffer.append(version);
		buffer.append("|");
		buffer.append(timestamp);
		buffer.append("|");
		buffer.append(token);
		buffer.append("|");
		buffer.append(username);
		
		return buffer.toString().getBytes("UTF-8");
	}
	
	@SuppressWarnings("unchecked")
	private boolean parseJSON(String json, List<Object> results) throws IOException {
		
		try {
			if(Objects.isNull(engine)) {
				ScriptEngineManager sem = new ScriptEngineManager();
				engine = sem.getEngineByName("javascript");
			}
			Object result = engine.eval("Java.asJSONCompatible(" + json + ")");
			if (result instanceof Map) {
				results.add(result);
				return true;
			} else if (result instanceof List) {
				results.addAll((List<Object>) result);
				return true;
			} else {
				throw new IOException("Unexpected result from json " + result.getClass().getName());
			}
		} catch (ScriptException e) {
			throw new IOException(e.getMessage(), e);
		}
	}
	
	public static void main(String[] args) throws IOException {
		
		UniversalAuthenticatorClient uac = new UniversalAuthenticatorClient();
		uac.register("t1@jadaptive.com", "Some Device", "gateway2.sshtools.com");
		
		uac.verifyRegistration();
		
		uac.authenticate("Some text");
	}
}
