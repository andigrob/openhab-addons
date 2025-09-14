package org.openhab.binding.meross.internal.mqtt;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Skeleton for Meross MQTT connector. Real connection logic and Meross-specific
 * signing / topics will be added in later steps.
 */
@NonNullByDefault
public class MerossMqttConnector {
    private final Logger logger = LoggerFactory.getLogger(MerossMqttConnector.class);

    private final List<MerossMqttListener> listeners = new CopyOnWriteArrayList<>();
    private final String baseHost;

    public MerossMqttConnector(String baseHost) {
        this.baseHost = baseHost;
    }

    public void addListener(MerossMqttListener listener) {
        listeners.add(listener);
    }

    public void removeListener(MerossMqttListener listener) {
        listeners.remove(listener);
    }

    public void connect() {
        logger.debug("MerossMqttConnector.connect() called (not implemented yet) host={}", baseHost);
    }

    public void disconnect() {
        logger.debug("MerossMqttConnector.disconnect() called (not implemented yet)");
    }

    public boolean isConnected() {
        return false; // placeholder
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
}
