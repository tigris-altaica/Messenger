package com.example.messenger;

import androidx.appcompat.app.AppCompatActivity;

import android.graphics.Typeface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private EditText editText;
    private Button sendButton;
    private LinearLayout msgList;

    private Socket socket;
    private InputStream input;
    private OutputStream output;
    private BufferedInputStream reader;

    private Cipher cipher;
    private SecretKeySpec secretKey;
    private DHParameterSpec ike2048() {
        final BigInteger p =
                new BigInteger(
                        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
                                + "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
                                + "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
                                + "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
                                + "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
                                + "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
                                + "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
                                + "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff",
                        16);
        final BigInteger g = new BigInteger("2");
        return new DHParameterSpec(p, g);
    }

    private class ConnectToServer extends AsyncTask<String, String, String> {

        @Override
        protected String doInBackground(String... strs) {
            try {
                socket = new Socket("10.0.2.2", 9779);
                output = socket.getOutputStream();
                input = socket.getInputStream();
                reader = new BufferedInputStream(input);

                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
                DHParameterSpec dhparams = ike2048();
                keyGen.initialize(dhparams);
                KeyPair keyPairA = keyGen.generateKeyPair();
                KeyAgreement kaA = KeyAgreement.getInstance("DH");
                kaA.init(keyPairA.getPrivate());

                byte[] keyApublic = keyPairA.getPublic().getEncoded();
                output.write(keyApublic);

                byte[] tempBuf = new byte[1024];
                int received = reader.read(tempBuf);
                byte[] keyBpublic = Arrays.copyOfRange(tempBuf, 0, received);

                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyBpublic);
                KeyFactory keyFactory = KeyFactory.getInstance("DH");
                PublicKey keyB = keyFactory.generatePublic(pubKeySpec);
                kaA.doPhase(keyB, true);
                byte[] SharedSecret = kaA.generateSecret();
                secretKey = new SecretKeySpec(SharedSecret, 0, 16, "AES");

                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (UnknownHostException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private class ReadThread extends AsyncTask<String, String, String> {

        @Override
        protected String doInBackground(String... strs) {
            while (true) {
                try {
                    byte[] tempBuf = new byte[1024];
                    int received = reader.read(tempBuf);
                    if (received != -1) {
                        byte[] ciphertext = Arrays.copyOfRange(tempBuf, 0, received);
                        cipher.init(Cipher.DECRYPT_MODE, secretKey);
                        String message = new String(cipher.doFinal(ciphertext));
                        publishProgress(message);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }
            }
        }

        @Override
        protected void onProgressUpdate(String... msgs) {
            TextView msgNew = new TextView(MainActivity.this);
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            params.setMargins(0, 0, 0, 20);
            msgNew.setLayoutParams(params);
            msgNew.setTextAlignment(View.TEXT_ALIGNMENT_TEXT_START);
            msgNew.setTextColor(getResources().getColor(R.color.black));
            msgNew.setTextSize(20);
            msgNew.setTypeface(null, Typeface.BOLD);
            msgNew.setBackgroundResource(R.color.white);
            msgNew.setText(msgs[0]);
            msgList.addView(msgNew);
        }
    }

    private class SendMessage extends AsyncTask<byte[], String, String> {

        @Override
        protected String doInBackground(byte[]... msgs) {
            try {
                byte[] cipherText = msgs[0];
                output.write(cipherText);
            } catch (UnknownHostException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        editText = findViewById(R.id.editText);
        sendButton = findViewById(R.id.sendButton);
        msgList = findViewById(R.id.msgList);

        new ConnectToServer().execute();
        new ReadThread().execute();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        try {
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void onClick(View view) {
        String message = editText.getText().toString();

        if (message.trim().equals(""))
            Toast.makeText(MainActivity.this, R.string.noInputText, Toast.LENGTH_SHORT).show();
        else {
            editText.getText().clear();

            TextView msgNew = new TextView(MainActivity.this);
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            params.setMargins(0, 0, 0, 20);
            msgNew.setLayoutParams(params);
            msgNew.setTextAlignment(View.TEXT_ALIGNMENT_TEXT_END);
            msgNew.setTextColor(getResources().getColor(R.color.black));
            msgNew.setTextSize(20);
            msgNew.setTypeface(null, Typeface.BOLD);
            msgNew.setBackgroundResource(R.color.light_blue);
            msgNew.setText(message);
            msgList.addView(msgNew);

            try {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] cipherText = cipher.doFinal(message.getBytes());
                new SendMessage().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, cipherText);
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        }
    }
}