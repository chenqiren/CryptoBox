package chenqiren.com.securesharedpreferences;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build.VERSION_CODES;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * SecureSharedPreferences provides secure data storing.
 *
 * The general flow is:
 * Save data:
 * 1. generate a AES key and an IV. The key is stored in keystore
 * 2. use the AES key and IV to encrypt user data.
 * 3. save encrypted user data and IV into SharedPreferences.
 *
 * Retrieve data:
 * 1. retrieve the encrypted user data and IV from SharedPreferences.
 * 2. retrieve the AES from keystore.
 * 3. use it and the IV to decrypt encrypted user data.
 *
 * This class is used for api above 23.
 * See {@link SecureSharedPreferences} for api below 23.
 */
@TargetApi(VERSION_CODES.M)
public class SecureSharedPreferencesM extends AbstractSecureSharedPreferences {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public SecureSharedPreferencesM(Context context) throws
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
                | NoSuchPaddingException e) {
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
                | InvalidAlgorithmParameterException
                | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public void clear() {
        mSharedPreferences.edit().clear().apply();
    }

    private EncryptedData encryptData(String input) throws
            BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, UnrecoverableEntryException, InvalidKeyException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, generateSecretKey(ALIAS));
        byte[] iv = cipher.getIV();
        byte[] encodedBytes = cipher.doFinal(input.getBytes());

        return new EncryptedData(
                Base64.encodeToString(encodedBytes, Base64.DEFAULT),
                Base64.encodeToString(iv, Base64.DEFAULT));
    }

    private String decryptData(final String alias, final EncryptedData encryptedData) throws
            UnrecoverableEntryException,
            NoSuchAlgorithmException,
            KeyStoreException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException,
            InvalidAlgorithmParameterException, NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        if (encryptedData == null) {
            return null;
        }

        byte[] iv = Base64.decode(encryptedData.iv, Base64.DEFAULT);
        final GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(alias), spec);

        byte[] encryptedDataBytes = Base64.decode(encryptedData.data, Base64.DEFAULT);

        return new String(cipher.doFinal(encryptedDataBytes));
    }

    /**
     * Generate a AES key which is used for encrypt/decrypt user data.
     * If the key is found in keystore, we use it. Otherwise create a new key and store it in keystore.
     */
    @NonNull
    private SecretKey generateSecretKey(final String alias) throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidAlgorithmParameterException,
            UnrecoverableEntryException,
            KeyStoreException {
        if (mKeyStore.containsAlias(ALIAS)) {
            return getSecretKey(alias);
        }

        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build());

        return keyGenerator.generateKey();
    }


    private SecretKey getSecretKey(final String alias) throws NoSuchAlgorithmException,
            UnrecoverableEntryException, KeyStoreException {
        return ((KeyStore.SecretKeyEntry) mKeyStore.getEntry(alias, null)).getSecretKey();
    }

    private static class EncryptedData {
        String data;
        String iv;

        public EncryptedData(String data, String iv) {
            this.data = data;
            this.iv = iv;
        }
    }
}
