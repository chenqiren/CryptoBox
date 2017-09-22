package chenqiren.com.securesharedpreferences;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import com.google.gson.Gson;

public abstract class AbstractSecureSharedPreferences {

    protected static final String SHARED_PREFERENCE_NAME = "SECURE_SHARED_PREFERENCE";
    protected static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    protected static final String ALIAS = "puppy_keystore";

    protected final Context mContext;
    protected final KeyStore mKeyStore;
    protected final SharedPreferences mSharedPreferences;
    protected final Gson mGson;

    public AbstractSecureSharedPreferences(Context context) throws
            NoSuchAlgorithmException,
            KeyStoreException,
            IOException,
            CertificateException {
        mContext = context;

        mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        mKeyStore.load(null);

        mSharedPreferences = context.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        mGson = new Gson();
    }

    public abstract void putString(@NonNull String key, @NonNull String value);

    public abstract String getString(@NonNull String key, @Nullable String defaultValue);

    public abstract void clear();
}
