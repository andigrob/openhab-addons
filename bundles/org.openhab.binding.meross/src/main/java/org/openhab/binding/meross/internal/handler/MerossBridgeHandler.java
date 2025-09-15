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
package org.openhab.binding.meross.internal.handler;

import java.io.File;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.openhab.binding.meross.internal.mqtt.MerossMqttConnector;
import org.openhab.binding.meross.internal.mqtt.MerossMqttListener;
import java.net.ConnectException;
import java.util.Collection;
import java.util.Set;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.meross.internal.api.MerossHttpConnector;
import org.openhab.binding.meross.internal.config.MerossBridgeConfiguration;
import org.openhab.binding.meross.internal.discovery.MerossDiscoveryService;
import org.openhab.binding.meross.internal.dto.HttpConnectorBuilder;
import org.openhab.binding.meross.internal.exception.MerossApiException;
import org.openhab.core.OpenHAB;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseBridgeHandler;
import org.openhab.core.thing.binding.ThingHandlerService;
import org.openhab.core.types.Command;

/**
 * The {@link MerossBridgeHandler} is responsible for handling http communication with and retrieve data from Meross
 * Host.
 *
 * @author Giovanni Fabiani - Initial contribution
 */
@NonNullByDefault
public class MerossBridgeHandler extends BaseBridgeHandler implements MerossMqttListener {
    private MerossBridgeConfiguration config = new MerossBridgeConfiguration();
    private @Nullable MerossHttpConnector merossHttpConnector;
    private final Logger logger = LoggerFactory.getLogger(MerossBridgeHandler.class);
    private @Nullable MerossMqttConnector mqttConnector;
    // Cached credential parts for MQTT message signing
    private @Nullable String cachedUserId;
    private @Nullable String cachedKey;
    private @Nullable String cachedAppId;
    private static final String CREDENTIAL_FILE_NAME = "meross" + File.separator + "meross_credentials.json";
    private static final String DEVICE_FILE_NAME = "meross" + File.separator + "meross_devices.json";
    public static final File CREDENTIALFILE = new File(
            OpenHAB.getUserDataFolder() + File.separator + CREDENTIAL_FILE_NAME);
    public static final File DEVICE_FILE = new File(OpenHAB.getUserDataFolder() + File.separator + DEVICE_FILE_NAME);
    // Map Meross device UUID -> ThingUID for garage doors (populated after device file load)
    private final java.util.concurrent.ConcurrentMap<String, org.openhab.core.thing.ThingUID> garageUuidMap =
            new java.util.concurrent.ConcurrentHashMap<>();
    // Track which garage door UUIDs have delivered at least one valid state
    private final java.util.Set<String> garageStateSeen = java.util.Collections
        .newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());
    // Throttle repeated GET retries triggered by heartbeat (uuid->epochMillis)
    private final java.util.concurrent.ConcurrentMap<String, Long> lastGarageGetAttempt = new java.util.concurrent.ConcurrentHashMap<>();
    // Map pending GET messageId -> uuid to resolve ACK without /appliance path
    private final java.util.concurrent.ConcurrentMap<String, String> pendingGarageGets = new java.util.concurrent.ConcurrentHashMap<>();
    // Track if a single retry was already scheduled for uuid
    // Track attempt index (1..3) for initial state acquisition
    private final java.util.concurrent.ConcurrentMap<String, Integer> garageInitAttempts = new java.util.concurrent.ConcurrentHashMap<>();

    public MerossBridgeHandler(Thing thing) {
        super((Bridge) thing);
    }

    @Override
    public void initialize() {
        config = getConfigAs(MerossBridgeConfiguration.class);

        if (config.hostName.isBlank() || config.userEmail.isBlank() || config.userPassword.isBlank()) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR);
            return;
        }

        MerossHttpConnector merossHttpConnectorLocal = merossHttpConnector = HttpConnectorBuilder.newBuilder()
                .setApiBaseUrl(config.hostName).setUserEmail(config.userEmail).setUserPassword(config.userPassword)
                .setCredentialFile(CREDENTIALFILE).setDeviceFile(DEVICE_FILE).build();

        if (merossHttpConnectorLocal == null) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR);
            return;
        }
        try {
            // Always fetch data first (credentials + devices). Ensures credentials file exists for MQTT domain.
            merossHttpConnectorLocal.fetchDataAsync();

            if (config.enableMqtt) {
                startMqttAsync(merossHttpConnectorLocal);
            } else {
                logger.debug("Meross MQTT disabled via configuration.");
            }
            updateStatus(ThingStatus.ONLINE);
        } catch (ConnectException | MerossApiException e) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR, e.getMessage());
        }
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
    }

    @Override
    public Collection<Class<? extends ThingHandlerService>> getServices() {
        return Set.of(MerossDiscoveryService.class);
    }

    public @Nullable MerossHttpConnector getMerossHttpConnector() {
        return merossHttpConnector;
    }

    public boolean isMqttEnabled() {
        return config.enableMqtt;
    }

    public @Nullable MerossMqttConnector getMqttConnector() {
        return mqttConnector;
    }

    // --- MerossMqttListener ---
    @Override
    public void onMessage(@Nullable String deviceUuid, String topic, byte[] payload) {
        String json = new String(payload, java.nio.charset.StandardCharsets.UTF_8);
        if (logger.isTraceEnabled()) {
            logger.trace("MQTT RX topic={} bytes={} snippet={}", topic, payload.length,
                    json.substring(0, Math.min(json.length(), 200)));
        }
        // Basic Meross PUSH parsing (header + namespace). Defensive: catch all exceptions so we do not break callback thread.
        try {
            var root = JsonParser.parseString(json);
            if (!root.isJsonObject()) {
                return;
            }
            var obj = root.getAsJsonObject();
            var header = obj.getAsJsonObject("header");
            if (header == null) {
                return;
            }
            String namespace = header.has("namespace") ? header.get("namespace").getAsString() : "";
            String method = header.has("method") ? header.get("method").getAsString() : "";
            boolean isPush = "PUSH".equalsIgnoreCase(method);
            boolean isAck = "ACK".equalsIgnoreCase(method) || "GETACK".equalsIgnoreCase(method);
            String messageId = header.has("messageId") ? header.get("messageId").getAsString() : "";
            String from = header.has("from") ? header.get("from").getAsString() : "";
            // Expected patterns: /appliance/<uuid>/subscribe or /app/<user>
            @Nullable String uuid = extractUuid(from);
            if (uuid == null && isAck && !messageId.isBlank()) {
                // Resolve uuid from pending GETs
                uuid = pendingGarageGets.remove(messageId);
                if (uuid != null) {
                    logger.debug("Resolved ACK messageId={} to uuid={} for initial GarageDoor state", messageId, uuid);
                }
            }
            if (isAck && namespace.startsWith("Appliance.GarageDoor")) {
                logger.trace("GarageDoor ACK namespace={} messageId={} from='{}' resolvedUuid={}", namespace, messageId, from, uuid);
            }
            JsonObject payloadObj = obj.getAsJsonObject("payload");
            // Heartbeat-based re-query: if we receive a system heartbeat and have not yet seen a state, re-issue GET (throttled)
            if (isPush && uuid != null && !garageStateSeen.contains(uuid)
                    && ("Appliance.System.All".equals(namespace) || "Appliance.System.Online".equals(namespace)
                            || namespace.toLowerCase().contains("heartbeat"))) {
                maybeRequestGarageState(uuid);
            }
            if (namespace.startsWith("Appliance.Control.Sensor.LatestX")) {
                handleSensorLatest(namespace, payloadObj);
            } else if (namespace.startsWith("Appliance.GarageDoor")) {
                if (isPush || isAck) {
                    handleGarageDoor(namespace, uuid, payloadObj);
                }
            } else {
                if (isPush) { // limit noise: only log unhandled PUSH namespaces
                    logger.debug("Unhandled Meross namespace={} (len={}B) method={}", namespace, payload.length,
                            method);
                }
            }
        } catch (Exception e) {
            logger.debug("Failed to parse Meross MQTT payload: {}", e.getMessage());
        }
    }

    private void handleSensorLatest(String namespace, @Nullable JsonObject payload) {
        if (payload == null) {
            return;
        }
        // Placeholder: could extract temperature/humidity/etc. when needed
        logger.trace("SensorLatest namespace={} keys={}", namespace, payload.keySet());
    }

    private void handleGarageDoor(String namespace, @Nullable String uuid, @Nullable JsonObject payload) {
        if (payload == null) {
            return;
        }
        try {
            // Observed payload variants:
            // 1) {"state":{"channel":0,"open":1,...}}
            // 2) {"state":[{"channel":0,"open":1,...}]}
            @Nullable Integer openVal = null;
            if (payload.has("state")) {
                if (payload.get("state").isJsonObject()) {
                    var state = payload.getAsJsonObject("state");
                    if (state.has("open")) {
                        openVal = safeInt(state, "open");
                        logGarageDoorState(state, openVal);
                    }
                } else if (payload.get("state").isJsonArray()) {
                    var arr = payload.getAsJsonArray("state");
                    if (!arr.isEmpty() && arr.get(0).isJsonObject()) {
                        var state0 = arr.get(0).getAsJsonObject();
                        if (state0.has("open")) {
                            openVal = safeInt(state0, "open");
                            logGarageDoorState(state0, openVal);
                        }
                    }
                }
            }
            if (openVal == null) {
                logger.trace("GarageDoor: no open value found keys={}", payload.keySet());
                return;
            }
            String status = switch (openVal) {
            case 1 -> "OPEN";
            case 0 -> "CLOSED";
            default -> "UNKNOWN";
            };
            // TODO: locate thing/channel and update state (Contact) -> OPEN/CLOSED
            logger.debug("GarageDoor interpreted state={} (openVal={}) uuid={}", status, openVal, uuid);
            if (uuid != null) {
                updateGarageDoorChannel(uuid, status);
                if (!"UNKNOWN".equals(status)) {
                    garageStateSeen.add(uuid);
                }
            } else {
                logger.trace("GarageDoor state parsed but uuid missing (method likely ACK from /app path)");
            }
        } catch (Exception e) {
            logger.debug("Error handling GarageDoor namespace {}: {}", namespace, e.getMessage());
        }
    }

    private void updateGarageDoorChannel(String uuid, String status) {
        var thingUID = garageUuidMap.get(uuid);
        if (thingUID == null) {
            logger.trace("No mapped ThingUID for garage uuid={} yet", uuid);
            return;
        }
        var thing = getThing();
        if (thingUID.equals(thing.getUID())) {
            // Bridge itself, ignore
            return;
        }
        // Iterate through bridge children and update state via callback
    var callback = getCallback(); // optional fallback, may be null
        for (Thing child : getThing().getThings()) {
            if (child.getUID().equals(thingUID)) {
                org.openhab.core.library.types.OpenClosedType state = switch (status) {
                case "OPEN" -> org.openhab.core.library.types.OpenClosedType.OPEN;
                case "CLOSED" -> org.openhab.core.library.types.OpenClosedType.CLOSED;
                default -> null;
                };
                if (state != null) {
                    var handler = child.getHandler();
                    if (handler instanceof MerossGarageDoorHandler doorHandler) {
                        doorHandler.updateDoorState(state);
                    } else if (callback != null) {
                        ChannelUID cu = new ChannelUID(child.getUID(),
                                org.openhab.binding.meross.internal.MerossBindingConstants.CHANNEL_GARAGEDOOR_STATE);
                        // Fallback path if a non-specific handler were present (unlikely scenario)
                        callback.stateUpdated(cu, state);
                    }
                    logger.debug("Updated garage door channel state={} uuid={} thing={}", status, uuid,
                            thingUID.getAsString());
                }
                return;
            }
        }
    }

    private @Nullable String extractUuid(@Nullable String from) {
        if (from == null || from.isBlank()) {
            return null;
        }
        // /appliance/<uuid>/subscribe
        int first = from.indexOf("/appliance/");
        if (first >= 0) {
            int start = first + "/appliance/".length();
            int nextSlash = from.indexOf('/', start);
            if (nextSlash > start) {
                return from.substring(start, nextSlash);
            }
        }
        return null;
    }

    private void buildGarageUuidMap(MerossHttpConnector httpConnector) {
        try {
            var devices = httpConnector.readDevices();
            if (devices == null) {
                return;
            }
            java.util.Map<String, org.openhab.core.thing.ThingUID> map = new java.util.HashMap<>();
            for (Thing child : getThing().getThings()) {
                if (child.getHandler() instanceof MerossGarageDoorHandler doorHandler) {
                    // match by doorName vs device devName
                    String doorName = doorHandler.getThing().getConfiguration().get("doorName") != null
                            ? doorHandler.getThing().getConfiguration().get("doorName").toString()
                            : doorHandler.getThing().getLabel();
                    if (doorName == null) {
                        continue;
                    }
                    devices.stream().filter(d -> doorName.equalsIgnoreCase(d.devName())).findFirst()
                            .ifPresent(d -> map.put(d.uuid(), child.getUID()));
                }
            }
            garageUuidMap.putAll(map);
            logger.debug("Built garage uuid map size={}", map.size());
        } catch (Exception e) {
            logger.debug("Failed building garage uuid map: {}", e.getMessage());
        }
    }

    private static @Nullable Integer safeInt(JsonObject obj, String key) {
        try {
            return obj.get(key).getAsInt();
        } catch (Exception e) {
            return null;
        }
    }

    private void logGarageDoorState(JsonObject stateObj, @Nullable Integer openVal) {
        if (openVal == null) {
            logger.trace("GarageDoor state object without open field keys={}", stateObj.keySet());
        } else {
            logger.trace("GarageDoor raw state open={} keys={}", openVal, stateObj.keySet());
        }
    }

    private String sanitizeHost(String host) {
        String h = host.trim();
        if (h.startsWith("https://")) {
            h = h.substring(8);
        } else if (h.startsWith("http://")) {
            h = h.substring(7);
        }
        // remove any leading // if present
        while (h.startsWith("//")) {
            h = h.substring(2);
        }
        // strip trailing slashes
        while (h.endsWith("/")) {
            h = h.substring(0, h.length() - 1);
        }
        return h;
    }

    private void startMqttAsync(MerossHttpConnector httpConnector) {
        scheduler.execute(() -> {
            try {
                var creds = httpConnector.readCredentials();
                int attempts = 0;
                while (creds == null && attempts < 5) { // wait up to ~5 * 2s = 10s
                    attempts++;
                    logger.debug("Waiting for Meross credentials (attempt {}/{})", attempts, 5);
                    Thread.sleep(2000);
                    creds = httpConnector.readCredentials();
                }
                if (creds == null) {
                    logger.debug("Credentials not available after wait window; skipping MQTT startup");
                    return;
                }
                String candidate = config.mqttHost.isBlank() ? (creds.mqttDomain() != null && !creds.mqttDomain().isBlank()
                        ? creds.mqttDomain() : config.hostName) : config.mqttHost;
                String sanitized = sanitizeHost(candidate);
                mqttConnector = new MerossMqttConnector(sanitized);
                mqttConnector.authenticate(creds.userId(), creds.key(), creds.token());
                cachedUserId = creds.userId();
                cachedKey = creds.key();
                logger.debug(
                        "Meross MQTT enabled (async connect) rawHost={} sanitized={} credsDomain={} explicitHostProvided={} credsPreloaded=true",
                        candidate, sanitized, creds.mqttDomain(), !config.mqttHost.isBlank());
                MerossMqttConnector connectorRef = mqttConnector;
                connectorRef.connect();
                if (connectorRef.isConnected()) {
                    connectorRef.addListener(this);
                    var userId = connectorRef.getUserId();
                    var appId = connectorRef.getAppId();
                    cachedAppId = appId;
                    java.util.List<String> topics = new java.util.ArrayList<>();
                    if (userId != null) {
                        topics.add("/app/" + userId + "/subscribe");
                        if (appId != null) {
                            topics.add("/app/" + userId + "-" + appId + "/subscribe");
                        }
                    }
                    topics = topics.stream().distinct().toList();
                    if (!topics.isEmpty()) {
                        logger.debug("Subscribing to Meross app topics: {}", topics);
                        connectorRef.subscribe(topics);
                        logger.info("Subscribed to {} Meross MQTT app topics", topics.size());
                        // Schedule initial GarageDoor state query shortly after subscribe (if credentials cached)
                        scheduler.schedule(() -> sendInitialGarageDoorGets(httpConnector), 3, java.util.concurrent.TimeUnit.SECONDS);
                        // Build UUID mapping for garage door things
                        scheduler.execute(() -> buildGarageUuidMap(httpConnector));
                    } else {
                        logger.debug("No Meross MQTT app topics assembled (userId/appId missing)");
                    }
                }
            } catch (Exception e) {
                logger.debug("MQTT startup failed: {}", e.getMessage());
            }
        });
    }

    private void sendInitialGarageDoorGets(MerossHttpConnector http) {
        var devices = http.readDevices();
        if (devices == null || devices.isEmpty()) {
            logger.debug("No devices available for initial GarageDoor GET");
            return;
        }
        for (var d : devices) {
            if ("msg100".equalsIgnoreCase(d.deviceType())) {
                sendGarageDoorGet(d.uuid());
            }
        }
    }

    private void sendGarageDoorGet(String uuid) {
        MerossMqttConnector c = mqttConnector;
        if (c == null || !c.isConnected()) {
            return;
        }
        String user = cachedUserId;
        String key = cachedKey;
        if (user == null || key == null) {
            logger.debug("Cannot sign GarageDoor GET (missing credentials)");
            return;
        }
        long ts = System.currentTimeMillis() / 1000L;
        String messageId = randomHex(32);
        String sign = md5(messageId + key + ts);
    // Prefer /app/<user>-<appId> path if appId known
    int attempt = garageInitAttempts.merge(uuid, 1, Integer::sum);
    // Ordered variants: 1) /app/<user>-<appId>
    //                    2) /app/<user>-<appId>/subscribe
    //                    3) /app/<user>/subscribe
    String base = "/app/" + user + (cachedAppId != null ? ("-" + cachedAppId) : "");
    String fromPath = switch (attempt) {
    case 1 -> base;
    case 2 -> base + "/subscribe";
    default -> "/app/" + user + "/subscribe";
    };
    // Minimal Meross GET frame
        String json = "{" +
                "\"header\":{" +
                "\"messageId\":\"" + messageId + "\"," +
                "\"namespace\":\"Appliance.GarageDoor.State\"," +
                "\"method\":\"GET\"," +
                "\"payloadVersion\":1," +
        "\"from\":\"" + fromPath + "\"," +
                "\"timestamp\":" + ts + "," +
                "\"sign\":\"" + sign + "\"}," +
                "\"payload\":{\"state\":{}}}";
        // Topic: app-level publish (Meross cloud usually expects /appliance/<uuid>/subscribe for sending commands, but we only have app topics; try device publish path for command).
    String topic = "/appliance/" + uuid + "/subscribe"; // revert to subscribe path for device command
        c.publish(topic, json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        pendingGarageGets.put(messageId, uuid);
        logger.debug("Sent GarageDoor GET attempt={} for uuid={} msgId={} topic={} fromPath={} (pending mapped)",
                attempt, uuid, messageId, topic, fromPath);
        if (!garageStateSeen.contains(uuid) && attempt < 3) {
            scheduler.schedule(() -> {
                if (!garageStateSeen.contains(uuid)) {
                    logger.debug("Re-attempting GarageDoor GET (attempt {}->{} uuid={})", attempt, attempt + 1, uuid);
                    sendGarageDoorGet(uuid);
                }
            }, 4, java.util.concurrent.TimeUnit.SECONDS);
        }
    }

    private void maybeRequestGarageState(String uuid) {
        long now = System.currentTimeMillis();
        Long last = lastGarageGetAttempt.get(uuid);
        if (last != null && (now - last) < 5000) { // 5s throttle
            return;
        }
        lastGarageGetAttempt.put(uuid, now);
        sendGarageDoorGet(uuid);
    }

    private static String md5(String s) {
        try {
            var md = java.security.MessageDigest.getInstance("MD5");
            byte[] dig = md.digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : dig) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String randomHex(int len) {
        java.security.SecureRandom r = new java.security.SecureRandom();
        byte[] b = new byte[len / 2];
        r.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte value : b) {
            sb.append(String.format("%02x", value));
        }
        return sb.toString();
    }
}
