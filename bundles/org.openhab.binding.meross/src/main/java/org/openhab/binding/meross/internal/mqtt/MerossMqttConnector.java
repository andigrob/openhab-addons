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
    public void connectionLost(Throwable cause) {
        connected = false;
        String msg = (cause != null ? cause.getMessage() : "<no message>");
        logger.debug("MQTT connection lost: {}", msg);
    }

    @Override
    public void messageArrived(String topic, MqttMessage message) throws Exception {
        if (topic == null || message == null) {
            return;
        }
        byte[] payload = message.getPayload();
        logger.trace("MQTT msg topic={} bytes={}", topic, payload.length);
        dispatch(null, topic, payload);
    }

    @Override
    public void deliveryComplete(IMqttDeliveryToken token) {
        // no-op
    }
}
