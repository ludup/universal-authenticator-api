# Universal Authenticator Java API
Universal Authenticator is a mobile app developed by JADAPTIVE Limited https://www.jadaptive.com. The app supports several authentication mechanisms, including SSH public-key authentication, Webauthn, TOTP, and it's own native mechanism. 

This API enables the creation of authentication solutions using the native method. It is suitable for server solutions that want to integrate native Universal Authentication into their authentication process. 

To support authentication, a user must first register the authenticating device with the app. In the scenario of implementing this in a web-based solution, the webserver is the authenticating device. 

The user registers the details of their Universal Authenticator account with the authenticating device. Typically this is an email address and the hostname of the JADAPTIVE Key Server where the app is registered. Once the user has provided this information, we can create an instance of the API and register the authenticating device.

```
UniversalAuthenticatorClient uac = new UniversalAuthenticatorClient();
uac.register("user@domain.com", "My Web Server", "gateway.sshtools.com");
```

As part of the registration process, the user must authorize access to the device through the Universal Authenticator app. If there is no exception once the register method returns, the registration is complete. We can verify the registration at any time using:

```
uac.verifyRegistration();
```

This does not perform any authentication, it just checks that the authorization token of the registration is valid with the Key Server.

Once returned, we can save the registration details to file.

```
uac.save(new File("registration.properties"));
```

If you prefer to store the details elsewhere, you can grab a Properties object which contains the following items

```username
authorization
deviceName
privateKey
hostname
port
```

You should store these details securely as they contain sensitive information. Similary any call to save should ensure that the file is only readable by your solution.

The user is now ready to start authenticating with their app. To authenticate the user, creating an instance of the API passing in the File or Properties object containing the registration details.

```
UniversalAuthenticatorClient uac = new UniversalAuthenticatorClient(new File("registration.properties"));
```

Call the authenticate method with some authorization text to display to the user, and optionally a binary payload to use as the authentication challenge. 

```
boolean authenticated = uac.authenticate("Do you want to login to My Web Server?");
```

The user will be prompted via the app to authorize the access attempt. When the user approves the request, the app signs the binary payload with its private key, which is verified by the API before returning a boolean result. If the method returns true, then authentication is safe, and you can log in the user to your solution. If false, the user has rejected the attempt, and login should not continue.


