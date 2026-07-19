package app.sillytavern.securemobile;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Insets;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.webkit.SslErrorHandler;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.CookieManager;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.UUID;

@SuppressWarnings("deprecation")
public class MainActivity extends Activity {
    private static final int FILE_CHOOSER_REQUEST = 4001;
    private static final int EXPECTED_GATEWAY_PORT = 38443;
    private static final String PREFS = "st_mobile";
    private static final String KEY_GATEWAY_ORIGIN = "gateway_origin";
    private static final String UPDATE_HOST = "raw.githubusercontent.com";
    private static final String UPDATE_RAW_PATH_PREFIX = "/SneakIrwin/SillyTavern-Mobile-apk/main/update/";
    private static final String UPDATE_MANIFEST_URL = "https://" + UPDATE_HOST + UPDATE_RAW_PATH_PREFIX + "latest.json";
    private static final String UPDATE_COMMIT_ACTION = "app.sillytavern.securemobile.UPDATE_COMMIT";
    private static final String UPDATE_CALLBACK_TOKEN_EXTRA = "app.sillytavern.securemobile.UPDATE_CALLBACK_TOKEN";
    private static final String KEY_UPDATE_SESSION_ID = "update_session_id";
    private static final String KEY_UPDATE_CALLBACK_TOKEN = "update_callback_token";
    private static final int UPDATE_CONNECT_TIMEOUT_MS = 10000;
    private static final int UPDATE_READ_TIMEOUT_MS = 30000;
    private static final int UPDATE_MANIFEST_MAX_BYTES = 65536;
    private static final long UPDATE_APK_MAX_BYTES = 200L * 1024L * 1024L;
    private static final String HOST_PAUSE_SCRIPT =
            "window.dispatchEvent(new Event('stMobileHostPause'));";
    private static final String HOST_RESUME_SCRIPT =
            "window.dispatchEvent(new Event('stMobileHostResume'));";

    private SharedPreferences preferences;
    private LinearLayout root;
    private LinearLayout pairingPanel;
    private WebView webView;
    private TextView webStatus;
    private EditText pairingInput;
    private Button forgetButton;
    private ValueCallback<Uri[]> fileCallback;
    private String pendingGatewayOrigin;
    private String pendingPairingPath;
    private boolean pendingMainFrameError;
    private boolean updateCheckStarted;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        preferences = getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        WebView.setWebContentsDebuggingEnabled(false);
        buildLayout();
        configureWebView();
        boolean startedPairing = handleIntent(getIntent());
        checkForUpdateOnLaunch();
        String gatewayOrigin = getGatewayOrigin();
        if (startedPairing) {
            return;
        }
        if (gatewayOrigin == null) {
            showPairingPanel();
        } else if (webView.getUrl() == null) {
            showWebView();
            webView.loadUrl(gatewayOrigin + "/");
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    @Override
    protected void onPause() {
        dispatchHostLifecycleEvent(HOST_PAUSE_SCRIPT);
        if (webView != null) {
            webView.onPause();
        }
        super.onPause();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (webView != null) {
            webView.onResume();
        }
        dispatchHostLifecycleEvent(HOST_RESUME_SCRIPT);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (hasFocus) {
            dispatchHostLifecycleEvent(HOST_RESUME_SCRIPT);
        }
    }

    private void dispatchHostLifecycleEvent(String script) {
        WebView currentWebView = webView;
        if (currentWebView == null || currentWebView.getUrl() == null) {
            return;
        }
        try {
            currentWebView.evaluateJavascript(script, null);
        } catch (IllegalStateException ignored) {
            // A renderer-loss callback will replace a dead WebView.
        }
    }

    private void buildLayout() {
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.rgb(11, 13, 15));
        root.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));

        pairingPanel = new LinearLayout(this);
        pairingPanel.setOrientation(LinearLayout.VERTICAL);
        pairingPanel.setGravity(Gravity.CENTER);
        int padding = dp(20);
        pairingPanel.setPadding(padding, padding, padding, padding);
        pairingPanel.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));

        TextView status = new TextView(this);
        status.setText(getString(R.string.not_paired));
        status.setTextColor(Color.WHITE);
        status.setTextSize(18);
        status.setGravity(Gravity.CENTER);

        pairingInput = new EditText(this);
        pairingInput.setSingleLine(true);
        pairingInput.setHint(getString(R.string.pairing_link_hint));
        pairingInput.setTextColor(Color.WHITE);
        pairingInput.setHintTextColor(Color.rgb(180, 180, 180));
        pairingInput.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        Button pairButton = new Button(this);
        pairButton.setText(getString(R.string.pair_button));
        pairButton.setOnClickListener((view) -> openPairingUrl(pairingInput.getText().toString().trim()));

        pairingPanel.addView(status);
        pairingPanel.addView(pairingInput);
        pairingPanel.addView(pairButton);

        webStatus = new TextView(this);
        webStatus.setTextColor(Color.WHITE);
        webStatus.setTextSize(14);
        webStatus.setGravity(Gravity.CENTER);
        webStatus.setPadding(padding, dp(10), padding, dp(10));
        webStatus.setBackgroundColor(Color.rgb(74, 24, 28));
        webStatus.setVisibility(View.GONE);

        webView = createWebView();

        forgetButton = new Button(this);
        forgetButton.setText(getString(R.string.forget_button));
        forgetButton.setVisibility(View.GONE);
        forgetButton.setOnClickListener((view) -> {
            preferences.edit().remove(KEY_GATEWAY_ORIGIN).apply();
            clearPendingPairing();
            webView.stopLoading();
            webView.loadUrl("about:blank");
            showPairingPanel();
        });

        root.addView(pairingPanel);
        root.addView(webStatus, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(webView);
        root.addView(forgetButton, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        setContentView(root);
        configureWindowInsets();
    }

    private WebView createWebView() {
        WebView view = new WebView(this);
        view.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f));
        return view;
    }

    private void configureWindowInsets() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            getWindow().setDecorFitsSystemWindows(false);
            root.setOnApplyWindowInsetsListener((view, windowInsets) -> {
                Insets systemBars = windowInsets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                Insets ime = windowInsets.getInsets(WindowInsets.Type.ime());
                int bottomInset = Math.max(systemBars.bottom, ime.bottom);
                if (root.getPaddingLeft() != systemBars.left
                        || root.getPaddingTop() != systemBars.top
                        || root.getPaddingRight() != systemBars.right
                        || root.getPaddingBottom() != bottomInset) {
                    root.setPadding(systemBars.left, systemBars.top, systemBars.right, bottomInset);
                }
                return windowInsets;
            });
            root.requestApplyInsets();
        }
    }

    private void configureWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(true);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setMediaPlaybackRequiresUserGesture(false);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (isAllowedGatewayUri(uri)) {
                    return false;
                }
                openExternal(uri);
                return true;
            }

            @Override
            @SuppressWarnings("deprecation")
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                Uri uri = Uri.parse(url);
                if (isAllowedGatewayUri(uri)) {
                    return false;
                }
                openExternal(uri);
                return true;
            }

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                handler.cancel();
                Uri errorUri = uriFromSslError(error);
                if (isPendingGatewayOrigin(errorUri)) {
                    clearPendingPairing();
                    showPairingPanel();
                    showInvalidPairingLink();
                } else if (isSavedGatewayOrigin(errorUri)) {
                    showGatewayLoadFailed();
                }
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                hideWebStatus();
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                commitPendingPairingIfReady(Uri.parse(url));
            }

            @Override
            public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
                if (request.isForMainFrame() && isPendingGatewayOrigin(request.getUrl())) {
                    pendingMainFrameError = true;
                    clearPendingPairing();
                    showPairingPanel();
                    showInvalidPairingLink();
                } else if (request.isForMainFrame() && isSavedGatewayOrigin(request.getUrl())) {
                    showGatewayLoadFailed();
                }
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame() && isPendingGatewayOrigin(request.getUrl())) {
                    pendingMainFrameError = true;
                    clearPendingPairing();
                    showPairingPanel();
                    showInvalidPairingLink();
                } else if (request.isForMainFrame() && isSavedGatewayOrigin(request.getUrl())) {
                    showGatewayLoadFailed();
                }
            }

            @Override
            public boolean onRenderProcessGone(WebView view, RenderProcessGoneDetail detail) {
                return recoverFromRenderProcessLoss(view);
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (fileCallback != null) {
                    fileCallback.onReceiveValue(null);
                }
                fileCallback = callback;
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
                try {
                    startActivityForResult(Intent.createChooser(intent, ""), FILE_CHOOSER_REQUEST);
                    return true;
                } catch (ActivityNotFoundException error) {
                    fileCallback = null;
                    return false;
                }
            }
        });
    }

    private boolean recoverFromRenderProcessLoss(WebView failedView) {
        if (failedView == null || failedView != webView || root == null) {
            return false;
        }
        String interruptedUrl = failedView.getUrl();
        int childIndex = root.indexOfChild(failedView);
        root.removeView(failedView);
        failedView.destroy();

        webView = createWebView();
        root.addView(webView, childIndex >= 0 ? childIndex : Math.max(0, root.getChildCount() - 1));
        configureWebView();

        if (interruptedUrl != null && isAllowedGatewayUri(Uri.parse(interruptedUrl))) {
            showWebView();
            webView.loadUrl(interruptedUrl);
            return true;
        }
        String gatewayOrigin = getGatewayOrigin();
        if (gatewayOrigin != null) {
            showWebView();
            webView.loadUrl(gatewayOrigin + "/");
        } else {
            clearPendingPairing();
            showPairingPanel();
        }
        return true;
    }

    private boolean handleIntent(Intent intent) {
        handleUpdateInstallCallback(intent);
        Uri data = intent == null ? null : intent.getData();
        if (data == null) {
            return false;
        }
        if ("stmobile".equals(data.getScheme()) && "pair".equals(data.getHost())) {
            boolean opened = openPairingUrl(data.getQueryParameter("url"));
            if (!opened && getGatewayOrigin() == null) {
                showPairingPanel();
            }
            return opened;
        }
        return false;
    }

    private boolean openPairingUrl(String url) {
        if (url == null || url.isEmpty()) {
            showInvalidPairingLink();
            return false;
        }

        Uri uri = Uri.parse(url);
        if (!isValidPairingUri(uri)) {
            showInvalidPairingLink();
            return false;
        }

        pendingGatewayOrigin = originFor(uri);
        pendingPairingPath = uri.getPath();
        pendingMainFrameError = false;
        showWebView();
        webView.loadUrl(uri.toString());
        return true;
    }

    private boolean isValidPairingUri(Uri uri) {
        return uri != null
                && "https".equals(uri.getScheme())
                && uri.getHost() != null
                && isPrivateLanHost(uri.getHost())
                && uri.getPort() == EXPECTED_GATEWAY_PORT
                && uri.getPath() != null
                && uri.getPath().startsWith("/__mobile/pair/");
    }

    private boolean isAllowedGatewayUri(Uri uri) {
        if (uri == null) {
            return false;
        }
        String origin = originFor(uri);
        String savedOrigin = getGatewayOrigin();
        return origin != null && (origin.equals(savedOrigin) || origin.equals(pendingGatewayOrigin));
    }

    private boolean isPendingPairingUri(Uri uri) {
        return pendingGatewayOrigin != null
                && uri != null
                && pendingGatewayOrigin.equals(originFor(uri))
                && pendingPairingPath != null
                && pendingPairingPath.equals(uri.getPath());
    }

    private boolean isPendingGatewayOrigin(Uri uri) {
        return pendingGatewayOrigin != null
                && uri != null
                && pendingGatewayOrigin.equals(originFor(uri));
    }

    private boolean isSavedGatewayOrigin(Uri uri) {
        String savedOrigin = getGatewayOrigin();
        return savedOrigin != null
                && uri != null
                && savedOrigin.equals(originFor(uri));
    }

    private void commitPendingPairingIfReady(Uri uri) {
        if (pendingGatewayOrigin == null || uri == null || !pendingGatewayOrigin.equals(originFor(uri))) {
            return;
        }
        if (pendingMainFrameError) {
            clearPendingPairing();
            return;
        }
        String path = uri.getPath();
        if (path == null || path.startsWith("/__mobile/pair/")) {
            return;
        }
        saveGatewayOrigin(pendingGatewayOrigin);
        CookieManager.getInstance().flush();
        clearPendingPairing();
    }

    private void clearPendingPairing() {
        pendingGatewayOrigin = null;
        pendingPairingPath = null;
        pendingMainFrameError = false;
    }

    private boolean isPrivateLanHost(String host) {
        if (host == null) {
            return false;
        }
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        int[] octets = new int[4];
        for (int i = 0; i < parts.length; i++) {
            try {
                octets[i] = Integer.parseInt(parts[i]);
            } catch (NumberFormatException error) {
                return false;
            }
            if (octets[i] < 0 || octets[i] > 255) {
                return false;
            }
        }
        return octets[0] == 10
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168);
    }

    private String originFor(Uri uri) {
        if (uri == null || uri.getScheme() == null || uri.getHost() == null) {
            return null;
        }
        StringBuilder origin = new StringBuilder();
        origin.append(uri.getScheme()).append("://").append(uri.getHost());
        if (uri.getPort() > 0) {
            origin.append(':').append(uri.getPort());
        }
        return origin.toString();
    }

    private Uri uriFromSslError(SslError error) {
        if (error == null || error.getUrl() == null) {
            return null;
        }
        return Uri.parse(error.getUrl());
    }

    private String getGatewayOrigin() {
        return preferences.getString(KEY_GATEWAY_ORIGIN, null);
    }

    private void saveGatewayOrigin(String origin) {
        preferences.edit().putString(KEY_GATEWAY_ORIGIN, origin).apply();
    }

    private void showPairingPanel() {
        hideWebStatus();
        pairingPanel.setVisibility(View.VISIBLE);
        webView.setVisibility(View.GONE);
        forgetButton.setVisibility(View.GONE);
    }

    private void showWebView() {
        pairingPanel.setVisibility(View.GONE);
        webView.setVisibility(View.VISIBLE);
        forgetButton.setVisibility(View.GONE);
    }

    private void hideWebStatus() {
        webStatus.setVisibility(View.GONE);
    }

    private void showGatewayLoadFailed() {
        webStatus.setText(getString(R.string.gateway_load_failed));
        webStatus.setVisibility(View.VISIBLE);
        showWebView();
        forgetButton.setVisibility(View.VISIBLE);
    }

    private void openExternal(Uri uri) {
        if (uri == null) {
            return;
        }
        Intent intent = new Intent(Intent.ACTION_VIEW, uri);
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException ignored) {
        }
    }

    private void showInvalidPairingLink() {
        Toast.makeText(this, getString(R.string.invalid_pairing_link), Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != FILE_CHOOSER_REQUEST || fileCallback == null) {
            return;
        }
        Uri[] results = WebChromeClient.FileChooserParams.parseResult(resultCode, data);
        fileCallback.onReceiveValue(results);
        fileCallback = null;
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private void checkForUpdateOnLaunch() {
        if (updateCheckStarted) {
            return;
        }
        updateCheckStarted = true;
        Thread updateThread = new Thread(() -> {
            try {
                UpdateManifest manifest = fetchUpdateManifest();
                if (manifest.versionCode <= getCurrentVersionCode()) {
                    return;
                }
                File apkFile = downloadUpdateApk(manifest);
                String actualSha256 = sha256Hex(apkFile);
                if (!actualSha256.equals(manifest.sha256)) {
                    deleteQuietly(apkFile);
                    runOnUiThread(() -> showUpdateVerifyFailed());
                    return;
                }
                if (!isDownloadedPackageExpected(apkFile, manifest)) {
                    deleteQuietly(apkFile);
                    runOnUiThread(() -> showUpdateVerifyFailed());
                    return;
                }
                runOnUiThread(() -> promptInstallVerifiedUpdate(apkFile, manifest));
            } catch (Exception ignored) {
                // Launch-time update checks must fail closed and keep the paired WebView usable.
            }
        }, "st-mobile-update-check");
        updateThread.start();
    }

    private UpdateManifest fetchUpdateManifest() throws Exception {
        HttpURLConnection connection = openUpdateConnection(UPDATE_MANIFEST_URL);
        try {
            String body = readBoundedString(connection, UPDATE_MANIFEST_MAX_BYTES);
            JSONObject json = new JSONObject(body);
            int versionCode = json.getInt("versionCode");
            String versionName = json.optString("versionName", "").trim();
            String apkUrl = json.optString("apkUrl", "").trim();
            String sha256 = json.optString("sha256", "").trim().toLowerCase(Locale.US);

            if (versionCode <= 0 || versionName.isEmpty() || !sha256.matches("[0-9a-f]{64}")) {
                throw new IOException("Invalid update manifest fields");
            }
            if (!isAllowedUpdateUri(Uri.parse(apkUrl))) {
                throw new IOException("Update APK URL is outside the allowed GitHub raw path");
            }
            return new UpdateManifest(versionCode, versionName, apkUrl, sha256);
        } finally {
            connection.disconnect();
        }
    }

    private File downloadUpdateApk(UpdateManifest manifest) throws Exception {
        HttpURLConnection connection = openUpdateConnection(manifest.apkUrl);
        try {
            long contentLength = connection.getContentLengthLong();
            if (contentLength > UPDATE_APK_MAX_BYTES) {
                throw new IOException("Unexpected update APK length");
            }

            File outputFile = new File(getCacheDir(), "SillyTavern-Mobile-update-" + manifest.versionCode + ".apk");
            File tempFile = new File(getCacheDir(), outputFile.getName() + ".tmp");
            deleteQuietly(outputFile);
            deleteQuietly(tempFile);

            try (InputStream input = new BufferedInputStream(connection.getInputStream());
                 OutputStream output = new FileOutputStream(tempFile)) {
                copyBounded(input, output, UPDATE_APK_MAX_BYTES);
            }
            if (tempFile.length() <= 0 || tempFile.length() > UPDATE_APK_MAX_BYTES) {
                throw new IOException("Unexpected downloaded update APK length");
            }

            if (!tempFile.renameTo(outputFile)) {
                throw new IOException("Could not move verified update APK into cache");
            }
            return outputFile;
        } finally {
            connection.disconnect();
        }
    }

    private HttpURLConnection openUpdateConnection(String urlString) throws IOException {
        if (!isAllowedUpdateUri(Uri.parse(urlString))) {
            throw new IOException("Update URL is outside the allowed GitHub raw path");
        }
        HttpURLConnection connection = (HttpURLConnection) new URL(urlString).openConnection();
        connection.setConnectTimeout(UPDATE_CONNECT_TIMEOUT_MS);
        connection.setReadTimeout(UPDATE_READ_TIMEOUT_MS);
        connection.setInstanceFollowRedirects(false);
        int status = connection.getResponseCode();
        if (status != HttpURLConnection.HTTP_OK) {
            connection.disconnect();
            throw new IOException("Unexpected update HTTP status: " + status);
        }
        return connection;
    }

    private boolean isAllowedUpdateUri(Uri uri) {
        return uri != null
                && "https".equals(uri.getScheme())
                && UPDATE_HOST.equalsIgnoreCase(uri.getHost())
                && uri.getPath() != null
                && uri.getPath().startsWith(UPDATE_RAW_PATH_PREFIX);
    }

    private String readBoundedString(HttpURLConnection connection, int maxBytes) throws IOException {
        try (InputStream input = new BufferedInputStream(connection.getInputStream());
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            copyBounded(input, output, maxBytes);
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    private long copyBounded(InputStream input, OutputStream output, long maxBytes) throws IOException {
        byte[] buffer = new byte[16384];
        long total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > maxBytes) {
                throw new IOException("Downloaded update exceeded expected size");
            }
            output.write(buffer, 0, read);
        }
        return total;
    }

    private String sha256Hex(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buffer = new byte[16384];
            int read;
            while ((read = input.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        byte[] hash = digest.digest();
        StringBuilder hex = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            hex.append(String.format(Locale.US, "%02x", b & 0xff));
        }
        return hex.toString();
    }

    private boolean isDownloadedPackageExpected(File apkFile, UpdateManifest manifest) {
        PackageInfo packageInfo = getPackageManager().getPackageArchiveInfo(apkFile.getAbsolutePath(), 0);
        return packageInfo != null
                && getPackageName().equals(packageInfo.packageName)
                && getVersionCode(packageInfo) == manifest.versionCode;
    }

    private long getCurrentVersionCode() throws PackageManager.NameNotFoundException {
        return getVersionCode(getPackageManager().getPackageInfo(getPackageName(), 0));
    }

    private long getVersionCode(PackageInfo packageInfo) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return packageInfo.getLongVersionCode();
        }
        return packageInfo.versionCode;
    }

    private void promptInstallVerifiedUpdate(File apkFile, UpdateManifest manifest) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !getPackageManager().canRequestPackageInstalls()) {
            Toast.makeText(this, getString(R.string.update_install_permission_needed), Toast.LENGTH_LONG).show();
            openUnknownAppSourceSettings();
            return;
        }

        try {
            installDownloadedApk(apkFile);
            Toast.makeText(this, getString(R.string.update_ready, manifest.versionName), Toast.LENGTH_LONG).show();
        } catch (Exception error) {
            Toast.makeText(this, getString(R.string.update_install_failed), Toast.LENGTH_LONG).show();
        }
    }

    private void openUnknownAppSourceSettings() {
        Intent intent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:" + getPackageName()));
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException error) {
            try {
                startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS));
            } catch (ActivityNotFoundException ignored) {
            }
        }
    }

    private void installDownloadedApk(File apkFile) throws Exception {
        PackageInstaller installer = getPackageManager().getPackageInstaller();
        PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL);
        params.setAppPackageName(getPackageName());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED);
        }

        int sessionId = installer.createSession(params);
        String callbackToken = UUID.randomUUID().toString();
        preferences.edit()
                .putInt(KEY_UPDATE_SESSION_ID, sessionId)
                .putString(KEY_UPDATE_CALLBACK_TOKEN, callbackToken)
                .apply();
        PackageInstaller.Session session = null;
        boolean committed = false;
        try {
            session = installer.openSession(sessionId);
            try (InputStream input = new BufferedInputStream(new FileInputStream(apkFile));
                 OutputStream output = session.openWrite("SillyTavern-Mobile-update.apk", 0, apkFile.length())) {
                copyBounded(input, output, UPDATE_APK_MAX_BYTES);
                session.fsync(output);
            }

            Intent callback = new Intent(this, MainActivity.class);
            callback.setAction(UPDATE_COMMIT_ACTION);
            callback.putExtra(UPDATE_CALLBACK_TOKEN_EXTRA, callbackToken);
            int flags = PendingIntent.FLAG_UPDATE_CURRENT;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                flags |= PendingIntent.FLAG_MUTABLE;
            }
            PendingIntent pendingIntent = PendingIntent.getActivity(this, sessionId, callback, flags);
            session.commit(pendingIntent.getIntentSender());
            committed = true;
        } finally {
            if (session != null) {
                session.close();
            }
            if (!committed) {
                installer.abandonSession(sessionId);
                clearExpectedUpdateCallback();
            }
        }
    }

    private void handleUpdateInstallCallback(Intent intent) {
        if (intent == null || !UPDATE_COMMIT_ACTION.equals(intent.getAction())) {
            return;
        }
        int sessionId = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1);
        int expectedSessionId = preferences.getInt(KEY_UPDATE_SESSION_ID, -1);
        String callbackToken = intent.getStringExtra(UPDATE_CALLBACK_TOKEN_EXTRA);
        String expectedCallbackToken = preferences.getString(KEY_UPDATE_CALLBACK_TOKEN, null);
        if (sessionId < 0 || sessionId != expectedSessionId
                || expectedCallbackToken == null || !expectedCallbackToken.equals(callbackToken)
                || !isOwnedUpdateSession(sessionId)) {
            return;
        }
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
        if (status != PackageInstaller.STATUS_PENDING_USER_ACTION) {
            clearExpectedUpdateCallback();
            return;
        }
        Intent confirmationIntent = intent.getParcelableExtra(Intent.EXTRA_INTENT);
        if (confirmationIntent == null) {
            clearExpectedUpdateCallback();
            return;
        }
        clearExpectedUpdateCallback();
        try {
            startActivity(confirmationIntent);
        } catch (ActivityNotFoundException error) {
            Toast.makeText(this, getString(R.string.update_install_failed), Toast.LENGTH_LONG).show();
        }
    }

    private boolean isOwnedUpdateSession(int sessionId) {
        for (PackageInstaller.SessionInfo sessionInfo
                : getPackageManager().getPackageInstaller().getMySessions()) {
            if (sessionInfo.getSessionId() == sessionId
                    && getPackageName().equals(sessionInfo.getAppPackageName())) {
                return true;
            }
        }
        return false;
    }

    private void clearExpectedUpdateCallback() {
        preferences.edit()
                .remove(KEY_UPDATE_SESSION_ID)
                .remove(KEY_UPDATE_CALLBACK_TOKEN)
                .apply();
    }

    private void showUpdateVerifyFailed() {
        Toast.makeText(this, getString(R.string.update_verify_failed), Toast.LENGTH_LONG).show();
    }

    private void deleteQuietly(File file) {
        if (file != null && file.exists()) {
            //noinspection ResultOfMethodCallIgnored
            file.delete();
        }
    }

    private static final class UpdateManifest {
        private final int versionCode;
        private final String versionName;
        private final String apkUrl;
        private final String sha256;

        private UpdateManifest(int versionCode, String versionName, String apkUrl, String sha256) {
            this.versionCode = versionCode;
            this.versionName = versionName;
            this.apkUrl = apkUrl;
            this.sha256 = sha256;
        }
    }
}
