/*
 * Copyright (c) 2010-2025 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.meross.internal.api;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.meross.internal.dto.CloudCredentials;
import org.openhab.binding.meross.internal.dto.Device;
import org.openhab.binding.meross.internal.exception.MerossApiException;
import org.openhab.binding.meross.internal.handler.MerossBridgeHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

/**
 * The {@link MerossHttpConnector} class is responsible for handling the Http functionality for connecting to the Meross
 * Host
 *
 * @author Giovanni Fabiani - Initial contribution
 */
@NonNullByDefault
public class MerossHttpConnector {
    private final Logger logger = LoggerFactory.getLogger(MerossHttpConnector.class);
    private static final String INITIAL_STRING = "23x17ahWarFH6w29";
    private static final long CONNECTION_TIMEOUT_SECONDS = 15;
    private @Nullable String token;
    private final String apiBaseUrl;
    private final String userEmail;
    private final String userPassword;
    private final File credentialFile;
    private final File deviceFile;
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.of(CONNECTION_TIMEOUT_SECONDS, ChronoUnit.SECONDS)).build();

    public MerossHttpConnector(String apiBaseUrl, String userEmail, String password, File credentialFile,
            File deviceFile) {
        this.apiBaseUrl = apiBaseUrl;
        this.userEmail = userEmail;
        this.userPassword = password;
        this.credentialFile = credentialFile;
        this.deviceFile = deviceFile;
    }

    /**
     * @param paramsData The params
     * @param uri The uri
     * @param path The path (endpoint)
     * @return The http response
     * @throws IOException if it fails to return the http response
     */
    @SuppressWarnings({ "null" }) // HttpClient API not annotated for nullness; body() guaranteed non-null
    private HttpResponse<String> postResponse(Map<String, String> paramsData, String uri, String path) throws IOException {
        String dataToSign;
        String encodedParams;
        String authorizationValue;
        String nonce = UUID.randomUUID().toString().replace("-", "").substring(0, 16).toUpperCase();
        long timestamp = Instant.now().toEpochMilli();
        encodedParams = encodeParams(paramsData);
        dataToSign = "%s%d%s%s".formatted(INITIAL_STRING, timestamp, nonce, encodedParams);
        String md5hash = MD5Util.getMD5String(dataToSign);
        Map<String, String> payloadMap = new HashMap<>();
        payloadMap.put("params", encodedParams);
        payloadMap.put("sign", md5hash);
        payloadMap.put("timestamp", String.valueOf(timestamp));
        payloadMap.put("nonce", nonce);
        String payload = new Gson().toJson(payloadMap);
        if (token != null) {
            authorizationValue = "Basic %s".formatted(token);
        } else {
            authorizationValue = "Basic";
        }
        HttpRequest postRequest = HttpRequest.newBuilder().uri(URI.create(uri + path))
                .header("Authorization", authorizationValue).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload)).build();
        try {
            HttpResponse<String> resp = client.sendAsync(postRequest, HttpResponse.BodyHandlers.ofString()).get();
            return resp;
        } catch (InterruptedException | ExecutionException e) {
            throw new IOException("Error while posting data", e);
        }
    }

    private static String encodeParams(Map<String, String> paramsData) {
        return Base64.getEncoder().encodeToString(new Gson().toJson(paramsData).getBytes());
    }

    /**
     * @return The http response to login request
     * @throws ConnectException throws exception if a login fail
     */
    public HttpResponse<String> login() throws ConnectException {
        Map<String, String> loginMap = Map.of("email", userEmail, "password", userPassword);
        try {
            return postResponse(loginMap, apiBaseUrl, MerossEnum.HttpEndpoint.LOGIN.value());
        } catch (IOException e) {
            throw new ConnectException("Error while logging in");
        }
    }

    /**
     * @return The apiStatus value. The default return value has been set to -1 as the OK(0) value is a
     *         significant value for the API
     */
    public int apiStatus() {
        try {
            return JsonParser.parseString(login().body()).getAsJsonObject().get("apiStatus").getAsInt();
        } catch (IOException e) {
            logger.debug("Couldn't get apiStatus");
        }
        return -1;
    }

    /**
     * @param devName The device name
     * @return The device UUID
     * @throws IOException if the device UUID cannot be retrieved
     */
    public String getDevUUIDByDevName(String devName) throws IOException {
        ArrayList<Device> devices = readDevices();
        if (devices == null) {
            return ""; // no devices file yet
        }
        Optional<String> uuid = devices.stream().filter(device -> device.devName().equals(devName)).map(Device::uuid)
                .findFirst();
        if (uuid.isPresent()) {
            return uuid.get();
        }
        return "";
    }

    private void setToken(String token) {
        this.token = token;
    }

    public void logout() {
        try {
            postResponse(Collections.emptyMap(), apiBaseUrl, MerossEnum.HttpEndpoint.LOGOUT.value());
        } catch (IOException e) {
            logger.debug("Cannot log out", e);
        }
    }

    /**
     * @return The credentials
     * @throws IOException if credentials could not be retrieved
     */
    public String fetchCredentials() throws IOException {
        JsonElement jsonElement = JsonParser.parseString(login().body());
        return jsonElement.getAsJsonObject().get("data").toString();
    }

    /**
     * @return The devices
     * @throws IOException if devices could not be retrieved
     */
    public String fetchDevices() throws IOException {
        CloudCredentials credentials = Objects
                .requireNonNull(new Gson().fromJson(fetchCredentials(), CloudCredentials.class));
        String token = credentials.token();
        setToken(token);
        Map<String, String> emptyMap = Collections.emptyMap();
        HttpResponse<String> response = postResponse(emptyMap, apiBaseUrl, MerossEnum.HttpEndpoint.DEV_LIST.value());
        JsonElement jsonElement = JsonParser.parseString(response.body());
        if (logger.isDebugEnabled()) {
            logger.debug("fetchDevices HTTP status={} bodyBytes={}", response.statusCode(), response.body().length());
        }
        JsonElement dataElem = jsonElement.getAsJsonObject().get("data");
        if (dataElem != null && dataElem.isJsonObject() && dataElem.getAsJsonObject().has("deviceList")) {
            JsonElement deviceList = dataElem.getAsJsonObject().get("deviceList");
            if (deviceList != null && deviceList.isJsonArray()) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Extracted deviceList with {} entries", deviceList.getAsJsonArray().size());
                }
                return deviceList.toString();
            }
        }
        // Fallback: return original data segment
        return dataElem != null ? dataElem.toString() : "[]";
    }

    /**
     * @param credentialFile The credentials' file to be written once credentials are fetched from cloud
     */
    public void fetchCredentialsAndWrite(File credentialFile) {
        String json = null;
        try {
            json = fetchCredentials();
        } catch (IOException e) {
            logger.debug("IOException while fetching credentials", e);
        }
        if (json != null) {
            writeFile(json, credentialFile);
        }
    }

    /**
     * @param deviceFile The device file to be written once devices are fetched from cloud
     */
    public void fetchDevicesAndWrite(File deviceFile) {
        String json = null;
        try {
            json = fetchDevices();
        } catch (IOException e) {
            logger.debug("IOException while fetching devices {}", e.getMessage());
        }
        if (json != null) {
            String trimmed = json.trim();
            // Detect placeholder / invalid content (object instead of expected array of devices)
            boolean placeholder = isPlaceholderDeviceJson(trimmed);
            if (placeholder) {
                // Never write a pure placeholder. If file already contains data we keep it; if it does not exist yet
                // we simply skip creation so discovery can retry later.
                if (deviceFile.exists() && deviceFile.length() > 4) {
                    logger.warn("Skipping device file overwrite with placeholder object '{}' (keeping existing list)");
                } else {
                    logger.debug("Not creating device file because response is placeholder '{}' (will rely on retry logic)");
                }
                return;
            }
            writeFile(json, deviceFile);
            logger.debug("Fetched devices JSON written ({} bytes) to {}", json.length(), deviceFile.getAbsolutePath());
            if (logger.isTraceEnabled()) {
                logger.trace("First 300 chars of devices JSON: {}", json.substring(0, Math.min(json.length(), 300)));
            }
        }
    }

    /**
     * @return The user's credentials
     */

    public @Nullable CloudCredentials readCredentials() {
        File file = new File(String.valueOf(credentialFile));
        CloudCredentials cloudCredentials = null;
        try {
            cloudCredentials = new Gson().fromJson(readFile(file), CloudCredentials.class);
        } catch (IOException | JsonSyntaxException e) {
            logger.error("Error while reading credentials from {}", file.getAbsolutePath());
        }
        return cloudCredentials;
    }

    /**
     * @return The user's devices
     */
    public @Nullable ArrayList<Device> readDevices() {
        TypeToken<ArrayList<Device>> type = new TypeToken<>() {
        };
        File file = new File(String.valueOf(deviceFile));
        @Nullable ArrayList<Device> devices = null;
        try {
            if (!file.exists()) {
                logger.debug("Device file does not exist yet: {}", file.getAbsolutePath());
            } else {
                String raw = readFile(file);
                if (logger.isTraceEnabled()) {
                    logger.trace("Raw device file content ({} bytes): {}", raw.length(),
                            raw.substring(0, Math.min(raw.length(), 300)));
                }
                String trimmed = raw.trim();
                if (isPlaceholderDeviceJson(trimmed)) {
                    logger.debug("Device file contains placeholder object; treating as no devices (will retry on next fetch)");
                    return new ArrayList<>();
                }
                devices = new Gson().fromJson(raw, type);
                if (devices == null || devices.isEmpty()) {
                    logger.debug("Parsed device list is empty (0 devices) from file {}", file.getAbsolutePath());
                } else {
                    logger.debug("Parsed {} devices from file {}", devices.size(), file.getAbsolutePath());
                }
            }
        } catch (IOException | JsonSyntaxException e) {
            logger.error("Error while reading devices from {}: {}", file.getAbsolutePath(), e.getMessage());
        }
        return devices;
    }

    /**
     * Expose device file path for diagnostics.
     */
    public String getDeviceFilePath() {
        return deviceFile.getAbsolutePath();
    }

    private String readFile(File file) throws IOException {
        return Files.readString(file.toPath());
    }

    private void writeFile(String content, File file) {
        File parentFile = file.getParentFile();
        if (parentFile != null) {
            parentFile.mkdirs();
        }
        try {
            Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
        } catch (FileNotFoundException e) {
            logger.error("Couldn't create file '{}'.", file.getPath(), e);
        } catch (IOException e) {
            logger.error("Couldn't write to file '{}'.", file.getPath(), e);
        }
    }

    public void fetchDataAsync() throws ConnectException, MerossApiException {
        HttpResponse<String> loginResp;
        try {
            loginResp = login();
        } catch (ConnectException ce) {
            throw ce; // propagate network failure
        }
        int httpStatusCode = loginResp.statusCode();
        if (httpStatusCode != 200) {
            throw new ConnectException();
        }
        int apiStatusCode = -1;
        try {
            var root = JsonParser.parseString(loginResp.body()).getAsJsonObject();
            apiStatusCode = root.get("apiStatus").getAsInt();
        } catch (Exception e) {
            logger.debug("Failed parsing apiStatus from login body: {}", e.getMessage());
        }
        String apiMessage = MerossEnum.ApiStatusCode.getMessageByApiStatusCode(apiStatusCode);
        if (apiStatusCode == MerossEnum.ApiStatusCode.TOO_MANY_TOKENS.value()) {
            // Graceful degradation: reuse existing credential file if present
            if (credentialFile.exists()) {
                logger.warn("Meross login hit TOO_MANY_TOKENS; reusing existing credentials file {} and continuing", credentialFile.getName());
                // Attempt to load token from existing credentials file so that subsequent calls are authorized
                CloudCredentials existing = readCredentials();
                if (existing != null && existing.token() != null && !existing.token().isBlank()) {
                    setToken(existing.token());
                    logger.debug("Reused existing Meross token (len={}) after TOO_MANY_TOKENS", existing.token().length());
                } else {
                    logger.warn("Existing credentials file present but token missing/blank; device fetch likely to fail");
                }
            } else {
                throw new MerossApiException(apiMessage != null ? apiMessage : "TOO_MANY_TOKENS");
            }
        } else if (apiStatusCode != MerossEnum.ApiStatusCode.OK.value()) {
            throw new MerossApiException(apiMessage != null ? apiMessage : "API_ERROR" );
        } else {
            // Only fetch & overwrite credentials if login succeeded normally (avoid extra token churn)
            CompletableFuture.runAsync(() -> fetchCredentialsAndWrite(MerossBridgeHandler.CREDENTIALFILE))
                    .thenRunAsync(() -> fetchDevicesAndWrite(MerossBridgeHandler.DEVICE_FILE))
                    .thenRunAsync(this::logout).exceptionally(e -> {
                        logger.debug("Cannot fetch data {}", e.getMessage());
                        return null;
                    }).join();
            return; // done
        }
        // In fallback path (token reuse), attempt device fetch if device file missing OR placeholder
        if (credentialFile.exists()) {
            boolean needFetch = !MerossBridgeHandler.DEVICE_FILE.exists();
            boolean placeholder = false;
            if (!needFetch) {
                try {
                    String existing = readFile(MerossBridgeHandler.DEVICE_FILE);
                    placeholder = isPlaceholderDeviceJson(existing.trim());
                    if (placeholder) {
                        logger.warn("Existing Meross device file is placeholder; forcing refetch despite token reuse");
                        needFetch = true;
                    }
                } catch (IOException e) {
                    logger.debug("Could not read existing device file to check placeholder: {}", e.getMessage());
                }
            }
            if (needFetch) {
                // Limited retry loop (e.g. 2 attempts) in case first fetch returns placeholder again
                int attempts = 0;
                final int maxAttempts = 2;
                while (attempts < maxAttempts) {
                    attempts++;
                    CompletableFuture.runAsync(() -> fetchDevicesAndWrite(MerossBridgeHandler.DEVICE_FILE)).exceptionally(e -> {
                        logger.debug("Cannot fetch devices after token reuse {}", e.getMessage());
                        return null;
                    }).join();
                    try {
                        if (MerossBridgeHandler.DEVICE_FILE.exists()) {
                            String content = readFile(MerossBridgeHandler.DEVICE_FILE).trim();
                            if (!isPlaceholderDeviceJson(content)) {
                                logger.debug("Device fetch attempt {} produced non-placeholder content ({} bytes)", attempts, content.length());
                                break;
                            } else {
                                logger.debug("Device fetch attempt {} still placeholder; {}", attempts, attempts < maxAttempts ? "retrying" : "giving up");
                                // Sleep small backoff before retrying
                                if (attempts < maxAttempts) {
                                    try { Thread.sleep(500L); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                                }
                            }
                        }
                    } catch (IOException e) {
                        logger.debug("Error reading device file after attempt {}: {}", attempts, e.getMessage());
                    }
                }
            } else {
                logger.debug("Skipping device fetch on token reuse; existing device file considered valid: {}", MerossBridgeHandler.DEVICE_FILE.getAbsolutePath());
            }
        }
    }

    /**
     * Determines if the returned device JSON is a placeholder (empty object or object without any device-like markers)
     * instead of the expected array. This avoids persisting useless placeholders that block discovery retries.
     */
    private boolean isPlaceholderDeviceJson(String trimmed) {
        if (trimmed.isEmpty()) {
            return true;
        }
        if ("{}".equals(trimmed)) {
            return true;
        }
        if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
            return false; // proper array
        }
        // Heuristic: object but missing common device indicators
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            String lower = trimmed.toLowerCase();
            if (!lower.contains("devname") && !lower.contains("uuid") && !lower.contains("devicetype") && !lower.contains("deviceid")) {
                return true;
            }
        }
        return false;
    }
}
