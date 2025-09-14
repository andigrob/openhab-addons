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

    public MerossMqttConnector(String brokerHost) {
        this.brokerHost = brokerHost;
    }

    public void addListener(MerossMqttListener listener) {
        listeners.add(listener);
    }

    public void removeListener(MerossMqttListener listener) {
        listeners.remove(listener);
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
            // Auth to be added later (username/password/signature)
            logger.debug("Connecting to Meross MQTT broker {}", uri);
            client.connect(opts);
            connected = true;
            logger.info("Meross MQTT connected to {}", uri);
            // Subscriptions will be added later
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
     * Placeholder for future Meross specific authentication (username/password or signature).
     * Currently a no-op – Meross cloud seems to accept token-derived credentials which will be added later.
     */
    public void authenticate(String userId, String key, String token) {
        // Intentionally left blank; actual Meross signing to be implemented in follow-up.
        logger.trace("authenticate() called (deferred implementation) userId={}", userId);
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
        // assume ssl over 443 if not specified (placeholder); actual Meross may use different port
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
}
