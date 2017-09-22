package chenqiren.com.securesharedpreferences;

import android.content.Context;
import android.os.Build;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class SecureSharedPreferencesWrapper {

    private AbstractSecureSharedPreferences mSecureSharedPreferences;

    private static class SecureSharedPreferencesWrapperHolder {
        private static final SecureSharedPreferencesWrapper INSTANCE = new SecureSharedPreferencesWrapper();
    }

    public static SecureSharedPreferencesWrapper getInstance() {
        return SecureSharedPreferencesWrapperHolder.INSTANCE;
    }

    private SecureSharedPreferencesWrapper() { }

    public AbstractSecureSharedPreferences getSecureSharedPreferences(Context context) {
        if (mSecureSharedPreferences != null) {
            return mSecureSharedPreferences;
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                mSecureSharedPreferences = new SecureSharedPreferencesM(context);
            } else {
                mSecureSharedPreferences = new SecureSharedPreferences(context);
            }
        } catch (NoSuchAlgorithmException
                | KeyStoreException
                | IOException
                | CertificateException e) {
            throw new RuntimeException(e);
        }

        return mSecureSharedPreferences;
    }

}
