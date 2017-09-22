package chenqiren.com.securesharedpreferences;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

/**
 * SecureSharedPreferences provides secure data storing.
 *
 * The general flow is:
 * Save data:
 * 1. generate a AES key. use this key to encrypt user data.
 * 2. generate a RSA key. use this key to encrypt the AES key in step1.
 *    The RSA key is stored in keystore.
 * 3. save the encrypted user data and encrypted AES key into SharePreferences.
 *
 * Retrieve data:
 * 1. retrieve the encrypted user data and encrypted AES key from SharedPreferences.
 * 2. retrieve the RSA key from keystore.
 * 3. decrypt ASE key by using the RSA key.
 * 4. decrypt encrypted user data by using the decrypted ASE key.
 *
 * This class is used for api below 23.
 * See {@link SecureSharedPreferencesM} for api above 23.
 */
public class SecureSharedPreferences extends AbstractSecureSharedPreferences {

    private static final String RSA_TRANSFORMATION =  "RSA/ECB/PKCS1Padding";
    private static final String ASE_TRANSFORMATION = "AES/ECB/PKCS7Padding";

    public SecureSharedPreferences(Context context) throws
            NoSuchAlgorithmException,
            KeyStoreException,
            IOException,
            CertificateException {
        super(context);
    }

    public void putString(@NonNull String key, @NonNull String value) {
        if (TextUtils.isEmpty(key) || TextUtils.isEmpty(value)) {
            return;
        }

        EncryptedData encryptedData;
        try {
            encryptedData = encryptData(value);
        } catch (BadPaddingException
                | IllegalBlockSizeException
                | NoSuchAlgorithmException
                | InvalidKeyException
                | UnrecoverableEntryException
                | InvalidAlgorithmParameterException
                | NoSuchProviderException
                | KeyStoreException
                | NoSuchPaddingException
                | IOException e) {
            throw new RuntimeException(e);
        }

        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putString(key, mGson.toJson(encryptedData));
        editor.apply();
    }

    public String getString(@NonNull String key, @Nullable String defaultValue) {
        String encryptedResult = mSharedPreferences.getString(key, defaultValue);
        if (encryptedResult == null) {
            return null;
        }

        EncryptedData encryptedData = mGson.fromJson(encryptedResult, EncryptedData.class);

        try {
            return decryptData(ALIAS, encryptedData);
        } catch (NoSuchAlgorithmException
                | UnrecoverableEntryException
                | KeyStoreException
                | InvalidKeyException
                | BadPaddingException
                | IllegalBlockSizeException
                | NoSuchPaddingException
                | NoSuchProviderException
                | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void clear() {
        mSharedPreferences.edit().clear().apply();
    }

    private EncryptedData encryptData(String input) throws
            UnrecoverableEntryException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            IOException,
            BadPaddingException,
            IllegalBlockSizeException,
            InvalidAlgorithmParameterException {
        Key aseKey = new SecretKeySpec(generateASEKey(), "ASE");
        Cipher cipher = Cipher.getInstance(ASE_TRANSFORMATION, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, aseKey);

        byte[] encodedBytes = cipher.doFinal(input.getBytes());
        byte[] encodedKey = encryptKey(ALIAS, aseKey.getEncoded());

        return new EncryptedData(
                Base64.encodeToString(encodedBytes, Base64.DEFAULT),
                Base64.encodeToString(encodedKey, Base64.DEFAULT));
    }

    private String decryptData(final String alias, final EncryptedData encryptedData) throws
            NoSuchPaddingException,
            InvalidKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            UnrecoverableEntryException,
            IOException,
            BadPaddingException,
            IllegalBlockSizeException {
        byte[] decryptedKey = decryptKey(alias, encryptedData.encryptedKey);
        Key aseKey = new SecretKeySpec(decryptedKey, "ASE");
        Cipher cipher = Cipher.getInstance(ASE_TRANSFORMATION, "AndroidOpenSSL");
        cipher.init(Cipher.DECRYPT_MODE, aseKey);

        byte[] encryptedBytes = Base64.decode(encryptedData.encryptedData, Base64.DEFAULT);
        byte[] decodedBytes = cipher.doFinal(encryptedBytes);
        return new String(decodedBytes);
    }

    /**
     * This is used to encrypt the ASE key we used to encrypt data.
     * We save the encrypted key into SharePreferences.
     */
    private byte[] encryptKey(String alias, byte[] secretKey) throws
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException,
            KeyStoreException, InvalidKeyException, IOException {
        KeyPair keyPair = generateSecretKey(alias);
        Cipher inputCipher = Cipher.getInstance(RSA_TRANSFORMATION, "AndroidOpenSSL");
        inputCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
        cipherOutputStream.write(secretKey);
        cipherOutputStream.close();

        return outputStream.toByteArray();
    }

    /**
     * Decrypt the encrypted ASE key.
     */
    private byte[] decryptKey(String alias, String encryptedKey) throws
            UnrecoverableEntryException,
            NoSuchAlgorithmException,
            KeyStoreException,
            NoSuchProviderException,
            NoSuchPaddingException,
            InvalidKeyException,
            IOException {
        KeyPair keyPair = getSecretKey(alias);
        Cipher output = Cipher.getInstance(RSA_TRANSFORMATION, "AndroidOpenSSL");
        output.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] encyptedKeyBytes = Base64.decode(encryptedKey, Base64.DEFAULT);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(encyptedKeyBytes);
        CipherInputStream cipherInputStream = new CipherInputStream(inputStream, output);
        List<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte)nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for(int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i).byteValue();
        }
        return bytes;
    }

    private byte[] generateASEKey() {
        byte[] ASEkey = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ASEkey);

        return ASEkey;
    }

    /**
     * Generate a RSA key which is used for encrypt/decrypt the AES key.
     * The RSA key stored in keystore.
     */
    @NonNull
    private KeyPair generateSecretKey(final String alias) throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            UnrecoverableEntryException,
            KeyStoreException {
        if (mKeyStore.containsAlias(ALIAS)) {
            return getSecretKey(alias);
        }

        // Generate a key pair for encryption
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(mContext)
                .setAlias(ALIAS)
                .setSubject(new X500Principal("CN=" + ALIAS))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);
        kpg.initialize(spec);

        return kpg.generateKeyPair();
    }

    /**
     * Find the RSA key from keystore.
     */
    private KeyPair getSecretKey(final String alias) throws
            NoSuchAlgorithmException,
            UnrecoverableEntryException,
            KeyStoreException {
        PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) mKeyStore.getEntry(alias, null);
        return new KeyPair(privateKeyEntry.getCertificate().getPublicKey(), privateKeyEntry.getPrivateKey());
    }

    private static class EncryptedData {
        String encryptedData;
        String encryptedKey;

        public EncryptedData(String encryptedData, String encryptedKey) {
            this.encryptedData = encryptedData;
            this.encryptedKey = encryptedKey;
        }
    }
}
