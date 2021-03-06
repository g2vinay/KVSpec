// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.azure.messaging.servicebus.perf;

import com.azure.core.util.IterableStream;
import com.azure.core.util.logging.ClientLogger;
import com.azure.messaging.servicebus.ServiceBusMessage;
import com.azure.messaging.servicebus.ServiceBusReceivedMessage;
import com.azure.messaging.servicebus.models.ServiceBusReceiveMode;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Performance test.
 */
public class ReceiveAndDeleteMessageTest extends ServiceTest<ServiceBusStressOptions> {
    private final ClientLogger logger = new ClientLogger(ReceiveAndDeleteMessageTest.class);
    private final ServiceBusStressOptions options;
    private Flux<ServiceBusReceivedMessage> receiverFlux;

    /**
     * Creates test object
     * @param options to set performance test options.
     */
    public ReceiveAndDeleteMessageTest(ServiceBusStressOptions options) {
        super(options, ServiceBusReceiveMode.RECEIVE_AND_DELETE);
        this.options = options;
        receiverFlux = receiverAsync.receiveMessages().publish(1).autoConnect();
    }

    @Override
    public Mono<Void> setupAsync() {
        // Since test does warm up and test many times, we are sending many messages, so we will have them available.
        return Mono.defer(() -> {
            int total =  options.getMessagesToSend() * TOTAL_MESSAGE_MULTIPLIER;
            List<ServiceBusMessage> messages = new ArrayList<>();
            for (int i = 0; i < total; ++i) {
                ServiceBusMessage message = new ServiceBusMessage(CONTENTS);
                message.setMessageId(UUID.randomUUID().toString());
                messages.add(message);
            }
            return senderAsync.sendMessages(messages);
        });
    }

    @Override
    public void run() {

        int count = 0;
        while(count < options.getMessagesToReceive()) {
            IterableStream<ServiceBusReceivedMessage> messages = receiver
                .receiveMessages(options.getMessagesToReceive());
            for (ServiceBusReceivedMessage message : messages) {
                if (message.getBody() != null) {
                    count++;
                }
            }

            if (count <= 0) {
                throw logger.logExceptionAsWarning(new RuntimeException("Error. Should have received some messages."));
            }
        }
    }

    @Override
    public Mono<Void> runAsync() {
        return receiverFlux
            .take(options.getMessagesToReceive())
            .map(serviceBusReceivedMessageContext -> {
                return serviceBusReceivedMessageContext;
            }).then();
    }
}
