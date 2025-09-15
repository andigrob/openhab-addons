package org.openhab.binding.meross.internal.mqtt;

import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;

/**
 * Skeleton for Meross MQTT connector. Real connection logic and Meross-specific
 * signing / topics will be added in later steps.
 */
@NonNullByDefault
public class MerossMqttConnector implements MqttCallback {
    private final Logger logger = LoggerFactory.getLogger(MerossMqttConnector.class);

    private final List<MerossMqttListener> listeners = new CopyOnWriteArrayList<>();
    private final String brokerHost;
    private @Nullable MqttClient client;
    private volatile boolean connected = false;
    private String clientId = generatePrimaryClientId();
    private @Nullable String userId;
    private @Nullable String key;
    @SuppressWarnings("unused") // reserved for future use (may be needed for future authenticated topics)
    private @Nullable String token; // reserved

    public MerossMqttConnector(String brokerHost) {
        this.brokerHost = brokerHost;
    }

    public void addListener(MerossMqttListener listener) {
        listeners.add(listener);
    }

    public void removeListener(MerossMqttListener listener) {
        listeners.remove(listener);
    }

    /**
     * Store credentials for subsequent connect(). Password pattern: MD5(userId + key)
     */
    public void authenticate(String userId, String key, String token) {
        this.userId = userId;
        this.key = key;
        this.token = token;
        logger.debug("Stored Meross MQTT credentials userId={} keyLen={} tokenLen={}", userId, key.length(),
                token.length());
    }

    public synchronized void connect() {
        if (connected) {
            return; // already connected
        }
        try {
            String uri = inferBrokerURI();
            client = new MqttClient(uri, clientId);
            client.setCallback(this);
            MqttConnectOptions opts = new MqttConnectOptions();
            opts.setAutomaticReconnect(true);
            opts.setCleanSession(true);
            opts.setKeepAliveInterval(30);
            try {
                opts.setMqttVersion(MqttConnectOptions.MQTT_VERSION_3_1_1);
            } catch (NoSuchFieldError e) {
                // ignore if constant not present in older lib
            }
            String localUser = userId; // copy volatile @Nullable to local
            String localKey = key;
            if (localUser != null && localKey != null) {
                String pwd = md5(localUser + localKey);
                opts.setUserName(localUser);
                opts.setPassword(pwd.toCharArray());
                logger.debug("Connecting to Meross MQTT broker {} user={} pwd(md5 user+key)={}… clientId={}", uri,
                        localUser, pwd.substring(0, Math.min(6, pwd.length())), clientId);
            } else {
                logger.debug(
                        "Connecting to Meross MQTT broker {} without credentials (expect auth failure) clientId={}", uri,
                        clientId);
            }
            client.connect(opts);
            connected = true;
            logger.info("Meross MQTT connected to {}", uri);
        } catch (MqttException e) {
            String msg = e.getMessage();
            logger.debug("MQTT connect failed: {}", msg);
            // Fallback strategy for auth errors: change clientId and try alternative password formulas once
            if (!connected && msg != null && msg.toLowerCase().contains("berechtigung") || (msg != null && msg.toLowerCase().contains("not authorized"))) {
                attemptFallback();
            }
        }
    }

    private void attemptFallback() {
        String localUser = userId;
        String localKey = key;
        if (localUser == null || localKey == null) {
            return; // nothing to do
        }
        // Try alternative clientId and password formulas
        String altClientId = generateSecondaryClientId(localUser);
    String tok = token != null ? token : "";
    String[] pwCandidates = new String[] { md5(localUser + localKey), md5(localUser + tok), localKey };
        for (String candidate : pwCandidates) {
            if (candidate == null || candidate.isEmpty()) {
                continue;
            }
            try {
                String uri = inferBrokerURI();
                clientId = altClientId;
                client = new MqttClient(uri, clientId);
                client.setCallback(this);
                MqttConnectOptions opts = new MqttConnectOptions();
                opts.setAutomaticReconnect(true);
                opts.setCleanSession(true);
                opts.setKeepAliveInterval(30);
                try {
                    opts.setMqttVersion(MqttConnectOptions.MQTT_VERSION_3_1_1);
                } catch (NoSuchFieldError e) {
                    // ignore
                }
                opts.setUserName(localUser);
                opts.setPassword(candidate.toCharArray());
                logger.debug("Fallback MQTT attempt user={} pwdVariantPrefix={} clientId={}", localUser,
                        candidate.substring(0, Math.min(6, candidate.length())), clientId);
                client.connect(opts);
                connected = true;
                logger.info("Meross MQTT connected after fallback using variant");
                return;
            } catch (MqttException ex) {
                logger.debug("Fallback variant failed: {}", ex.getMessage());
            }
        }
    }

    private String generatePrimaryClientId() {
        return "app:" + randomHex(32);
    }

    private String generateSecondaryClientId(String user) {
        return "app:" + user + "_" + randomHex(8);
    }

    private static String randomHex(int len) {
        SecureRandom r = new SecureRandom();
        byte[] b = new byte[len / 2];
        r.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte value : b) {
            sb.append(String.format("%02x", value));
        }
        return sb.toString();
    }

    public synchronized void disconnect() {
        try {
            if (client != null && connected) {
                client.disconnectForcibly(1000, 1000);
            }
        } catch (MqttException e) {
            logger.debug("Error during MQTT disconnect: {}", e.getMessage());
        } finally {
            connected = false;
            client = null;
        }
    }

    public boolean isConnected() {
        return connected;
    }

    /**
     * Expose the Meross cloud userId used for authentication (may be null if not yet authenticated).
     */
    public @Nullable String getUserId() {
        return userId;
    }

    /**
     * Extract pseudo appId from the clientId (pattern "app:<hex>" or "app:<user>_<hex>").
     * Returns the random hex part; null if unavailable.
     */
    public @Nullable String getAppId() {
        String cid = clientId;
        if (!cid.startsWith("app:")) {
            return null;
        }
        String rest = cid.substring(4);
        int us = rest.indexOf('_');
        if (us >= 0 && us + 1 < rest.length()) {
            return rest.substring(us + 1);
        }
        return rest.isEmpty() ? null : rest;
    }

    /**
     * Subscribe to a set of topics if connected. Silent no-op if disconnected.
     */
    public void subscribe(List<String> topics) {
        MqttClient c = client;
        if (!connected || c == null) {
            logger.debug("subscribe() called while not connected ({} topics)", topics.size());
            return;
        }
        for (String t : topics) {
            try {
                c.subscribe(t);
                logger.debug("Subscribed to topic {}", t);
            } catch (MqttException e) {
                int rc = e.getReasonCode();
                logger.debug("Failed subscribing to {} rc={} msg={}", t, rc, e.getMessage());
            }
        }
    }

    /**
     * Publish helper (QoS 1, retained=false) for future command SET messages.
     */
    public void publish(String topic, byte[] payload) {
        MqttClient c = client;
        if (!connected || c == null) {
            logger.debug("publish() called while not connected topic={} bytes={}", topic, payload.length);
            return;
        }
        MqttMessage msg = new MqttMessage(payload);
        msg.setQos(1);
        msg.setRetained(false);
        try {
            c.publish(topic, msg);
            logger.trace("Published bytes={} to {}", payload.length, topic);
        } catch (MqttException e) {
            logger.debug("Publish failed topic={} err={}", topic, e.getMessage());
        }
    }

    // Placeholder dispatch method for future use
    private void dispatch(@Nullable String deviceUuid, String topic, byte[] payload) {
        for (MerossMqttListener l : listeners) {
            try {
                l.onMessage(deviceUuid, topic, payload);
            } catch (Exception e) {
                logger.debug("Listener threw exception", e);
            }
        }
    }

    private String inferBrokerURI() {
        // Enforce TLS: transparently upgrade insecure tcp:// to ssl:// while warning the user.
        if (brokerHost.startsWith("tcp://")) {
            String hostPort = brokerHost.substring("tcp://".length());
            logger.warn("Insecure Meross MQTT scheme 'tcp://' detected; forcing TLS 'ssl://' for {}", hostPort);
            return hostPort.contains(":") ? ("ssl://" + hostPort) : ("ssl://" + hostPort + ":443");
        }
        if (brokerHost.startsWith("ssl://")) {
            return brokerHost;
        }
        // Plain hostname: append default TLS scheme/port
        return "ssl://" + brokerHost + ":443";
    }

    // --- MqttCallback ---
    @Override
    public void connectionLost(@Nullable Throwable cause) {
        connected = false;
        String msg = (cause != null ? cause.getMessage() : "<no message>");
        logger.debug("MQTT connection lost: {}", msg);
    }

    @Override
    public void messageArrived(@Nullable String topic, @Nullable MqttMessage message) throws Exception {
        if (topic == null || message == null) {
            return;
        }
        byte[] payload = message.getPayload();
        logger.trace("MQTT msg topic={} bytes={}", topic, payload.length);
        dispatch(null, topic, payload);
    }

    @Override
    public void deliveryComplete(@Nullable IMqttDeliveryToken token) {
        // no-op
    }

    private static String md5(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
