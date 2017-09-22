# SecureSharedPreferences

SecureSharedPreferences provides a way to store user data securely on Android.
Storing username/password/token in SharedPreferences is not secure. SecureSharedPreferences encrypts the data before storing it
into SharedPreferences and decrypts the encrypted user's data when retrieving it back. 

SecureSharedPreferences is based on KeyStore and SharedPreferences.
    
```
The Android Keystore system lets you store cryptographic keys in a container to 
make it more difficult to extract from the device.
```

KeyStore provides two functions:

1.  Randomly generates keys
2.  Securely stores the keys

## The general flow is:
1.  When you want to store a secrete, retrieve the key from KeyStore, encrypt the data with it, and then store the encrypted data in SharedPreferences.
2.  When you retrieve the secret, read the encrypted data from SharedPreferences, get the key from KeyStore and then use the key to decrypt the data.

Because your key is randomly generated and securely managed by KeyStore and nothing but your code can read it, the secrets are secured.
You also need a block cipher such as AES for the encryption.

That’s all it is in theory. In practice, an API change in Android M makes it a little tricky to implement. You essentially have to handle two cases: Android versions after M (API level 23) and Android version before that.

# CryptoBox

This is an example app to show how to use SecureSharedPreferences. 

