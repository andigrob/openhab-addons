package org.openhab.binding.meross.internal.mqtt;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;

/**
 * Callback interface for incoming Meross MQTT messages.
 * This is an early skeleton; payload parsing and namespaces will be added later.
 */
@NonNullByDefault
public interface MerossMqttListener {
    /**
     * Invoked when a raw MQTT message for a device arrives.
     * @param deviceUuid device identifier (may be null if undetermined)
     * @param topic raw topic
     * @param payload raw payload bytes
     */
    void onMessage(@Nullable String deviceUuid, String topic, byte[] payload);
}
