package org.openhab.binding.meross.internal.mqtt;

import java.util.List;
import java.util.UUID;
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
    private String clientId = "openhab-meross-" + UUID.randomUUID();
    private @Nullable String userId;
    private @Nullable String key;
    private @Nullable String token; // reserved for future use

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
        logger.debug("Stored Meross MQTT credentials userId={} keyLen={} tokenLen={}", userId,
                key != null ? key.length() : -1, token != null ? token.length() : -1);
    }

    public synchronized void connect() {
        if (connected) {
            return;
        }
        try {
            String uri = inferBrokerURI();
            client = new MqttClient(uri, clientId);
            client.setCallback(this);
            MqttConnectOptions opts = new MqttConnectOptions();
            opts.setAutomaticReconnect(true);
            opts.setCleanSession(true);
            if (userId != null && key != null) {
                String pwd = md5(userId + key);
                opts.setUserName(userId);
                opts.setPassword(pwd.toCharArray());
                logger.debug("Connecting to Meross MQTT broker {} user={} pwdSet=true clientId={}", uri, userId, clientId);
            } else {
                logger.debug(
                        "Connecting to Meross MQTT broker {} without credentials (expect auth failure) clientId={}", uri,
                        clientId);
            }
            client.connect(opts);
            connected = true;
            logger.info("Meross MQTT connected to {}", uri);
        } catch (MqttException e) {
            logger.debug("MQTT connect failed: {}", e.getMessage());
        }
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
                logger.debug("Failed subscribing to {}: {}", t, e.getMessage());
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
        if (brokerHost.startsWith("tcp://") || brokerHost.startsWith("ssl://")) {
            return brokerHost;
        }
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
