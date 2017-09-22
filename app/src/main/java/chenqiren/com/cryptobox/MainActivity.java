package chenqiren.com.cryptobox;

import chenqiren.com.securesharedpreferences.SecureSharedPreferencesWrapper;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.security.SecureRandom;

public class MainActivity extends Activity {

    private static final String TOKEN_NAME = "token";

    private TextView mTextView;
    private TextView mOriginalTokenTextView;
    private TextView mSecureTokenTextView;

    private SecureSharedPreferencesWrapper mSecureSharedPreferences;
    private SharedPreferences mSharedPreferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mSecureSharedPreferences = SecureSharedPreferencesWrapper.getInstance();
        mSharedPreferences = this.getSharedPreferences("insecure", Context.MODE_PRIVATE);

        mTextView = findViewById(R.id.login_result);
        mOriginalTokenTextView = findViewById(R.id.original_token);
        mSecureTokenTextView = findViewById(R.id.secure_token);
    }

    @Override
    protected void onResume() {
        super.onResume();

        String secureToken = mSecureSharedPreferences.getSecureSharedPreferences(this).getString(TOKEN_NAME, null);
        String token = mSharedPreferences.getString(TOKEN_NAME, null);

        mOriginalTokenTextView.setText(token);
        mSecureTokenTextView.setText(secureToken);

        if (TextUtils.equals(token, secureToken)) {
            mTextView.setText("retrieve token successfully");
        } else {
            mTextView.setText("retrieve token failed");
        }
    }

    @Override
    protected void onPause() {
        super.onPause();

        String randomToken = generateRandomToken();
        mSecureSharedPreferences.getSecureSharedPreferences(this).putString(TOKEN_NAME, randomToken);
        mSharedPreferences.edit().putString(TOKEN_NAME, randomToken).apply();

        Log.e("chenqiren1", "new token " + randomToken);
    }

    private String generateRandomToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[12];
        secureRandom.nextBytes(bytes);

        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }
}
