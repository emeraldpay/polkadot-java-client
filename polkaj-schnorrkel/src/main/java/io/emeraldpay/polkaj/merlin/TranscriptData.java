package io.emeraldpay.polkaj.merlin;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/**
 * A container class to simply hold all the necessary input data (label + messages) to construct the actual
 * transcript on Rust's side. Think of this as "the bag of currently necessary arguments".
 * The main idea of this class is to be easily portable to Rust using JNI.
 * It has no usage on its own on the Java side alone.
 */
@SuppressWarnings({"MismatchedQueryAndUpdateOfCollection", "FieldCanBeLocal"})
public class TranscriptData {
    // INTENTIONALITY: Those fields being of type ArrayList is essential for the JNI mappings on the Rust side

    // HACK:
    //  Semantically, the internal representation of the domainSeparationLabel should be a single byte[]
    //  Due to an unresolved issue with robusta (the rust lib) though,
    //  the field mapping from byte[] doesn't work as expected, so this is the current workaround.
    private final ArrayList<byte[]> domainSeparationLabel;

    private final ArrayList<byte[]> labels;
    private final ArrayList<byte[]> messages;

    public TranscriptData(byte[] domainSeparationLabel) {
        this.domainSeparationLabel = new ArrayList<>();
        this.domainSeparationLabel.add(domainSeparationLabel);
        this.labels = new ArrayList<>();
        this.messages = new ArrayList<>();
    }

    /**
     * Appends an ASCII encoded string message to the transcript with an ASCII encoded string label.
     * @param label the ASCII encoded label
     * @param message the ASCII encoded message
     */
    public void appendMessage(String label, String message) {
        appendMessage(label, message.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Appends a message to the transcript with an ASCII encoded string label.
     * @param label the ASCII encoded label
     * @param message the actual message (content)
     */
    public void appendMessage(String label, byte[] message) {
        appendMessage(label.getBytes(StandardCharsets.US_ASCII), message);
    }

    /**
     * Appends a message to the transcript.
     * @param label the label of the message
     * @param message the actual message (content)
     */
    public void appendMessage(byte[] label, byte[] message) {
        labels.add(label);
        messages.add(message);
    }
}
