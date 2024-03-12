package io.emeraldpay.polkaj.schnorrkel

import io.emeraldpay.polkaj.merlin.TranscriptData
import org.apache.commons.codec.binary.Hex
import spock.lang.Specification

import java.security.SecureRandom

class SchnorrkelNativeSpec extends Specification {

    Schnorrkel schnorrkel = new SchnorrkelNative()

    def key1 = new Schnorrkel.KeyPair(
            Hex.decodeHex("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"),
            Hex.decodeHex(
                    "28b0ae221c6bb06856b287f60d7ea0d98552ea5a16db16956849aa371db3eb51" +
                            "fd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca34"
            )
    )

    def "Can sign"() {
        when:
        def act = schnorrkel.sign("".bytes, key1)
        then:
        act != null
        act.length == 64
    }

    def "Throws error on short sk"() {
        when:
        schnorrkel.sign("".bytes,
                new Schnorrkel.KeyPair(
                        Hex.decodeHex("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"),
                        Hex.decodeHex(
                                "28b0"
                        )
                ))
        then:
        def t = thrown(SchnorrkelException)
        t.message.length() > 0
        t.message == "SecretKey must be 64 bytes in length"
    }

    def "Signature is valid"() {
        setup:
        byte[] msg = "hello".bytes
        when:
        byte[] signature = schnorrkel.sign(msg, key1)
        def act = schnorrkel.verify(signature, msg, key1)
        then:
        act
    }

    def "Modified signature is invalid"() {
        setup:
        byte[] msg = "hello".bytes
        when:
        byte[] signature = schnorrkel.sign(msg, key1)
        def initial = schnorrkel.verify(signature, msg, key1)
        then:
        initial

        when:
        signature[0] = (byte)(signature[0] + 1)
        def act = schnorrkel.verify(signature, msg, key1)
        then:
        !act
    }

    def "Different signature is invalid"() {
        setup:
        byte[] msg = "hello".bytes
        when:
        byte[] signature2 = schnorrkel.sign("hello2".bytes, key1)
        def act = schnorrkel.verify(signature2, msg, key1)
        then:
        !act
    }

    def "Throws error on invalid signature"() {
        setup:
        byte[] msg = "hello".bytes
        when:
        schnorrkel.verify(Hex.decodeHex("00112233"), msg, key1)
        then:
        thrown(SchnorrkelException)
    }

    def "Throws error on invalid pubkey"() {
        setup:
        byte[] msg = "hello".bytes
        when:
        byte[] signature = schnorrkel.sign(msg, key1)
        schnorrkel.verify(signature, msg, new Schnorrkel.PublicKey(Hex.decodeHex("11223344")))
        then:
        thrown(SchnorrkelException)
    }

    def "Generates working key"() {
        setup:
        def random = SecureRandom.instanceStrong
        byte[] msg = "hello".bytes
        when:
        def keypair = schnorrkel.generateKeyPair(random)
        then:
        keypair != null
        keypair.publicKey.length == Schnorrkel.PUBLIC_KEY_LENGTH
        keypair.secretKey.length == Schnorrkel.SECRET_KEY_LENGTH
        new BigInteger(1, keypair.publicKey) != BigInteger.ZERO
        new BigInteger(1, keypair.secretKey) != BigInteger.ZERO

        when:
        byte[] signature = schnorrkel.sign(msg, keypair)
        def act = schnorrkel.verify(signature, msg, keypair)
        then:
        act
    }

    def "Generates key from default Secure Random"() {
        when:
        def keypair = schnorrkel.generateKeyPair()
        then:
        keypair != null
        keypair.publicKey.length == Schnorrkel.PUBLIC_KEY_LENGTH
        keypair.secretKey.length == Schnorrkel.SECRET_KEY_LENGTH
        new BigInteger(1, keypair.publicKey) != BigInteger.ZERO
        new BigInteger(1, keypair.secretKey) != BigInteger.ZERO
    }

    def "Generates from seed"() {
        when:
        def keypair = schnorrkel.generateKeyPairFromSeed(Hex.decodeHex("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"))
        then:
        keypair != null
        keypair.publicKey.length == Schnorrkel.PUBLIC_KEY_LENGTH
        keypair.secretKey.length == Schnorrkel.SECRET_KEY_LENGTH
        new BigInteger(1, keypair.publicKey) != BigInteger.ZERO
        new BigInteger(1, keypair.secretKey) != BigInteger.ZERO
        Hex.encodeHexString(keypair.getPublicKey()) == "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a"
    }

    def "Derive key"() {
        setup:
        def seed = Hex.decodeHex("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e")
        def cc = Schnorrkel.ChainCode.from(Hex.decodeHex("14416c696365")) // Alice
        when:
        def base = schnorrkel.generateKeyPairFromSeed(seed)
        def keypair = schnorrkel.deriveKeyPair(base, cc)
        then:
        Hex.encodeHexString(keypair.getPublicKey()) == "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
    }

    def "Derive soft key"() {
        setup:
        def seed = Hex.decodeHex("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e")
        def cc = new Schnorrkel.ChainCode(Hex.decodeHex("0c666f6f00000000000000000000000000000000000000000000000000000000"))
        when:
        def base = schnorrkel.generateKeyPairFromSeed(seed)
        def keypair = schnorrkel.deriveKeyPairSoft(base, cc)
        then:
        Hex.encodeHexString(keypair.getPublicKey()) == "40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a"
    }

    def "Derive soft public key"() {
        setup:
        def pub = Hex.decodeHex("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")
        def cc = Schnorrkel.ChainCode.from(Hex.decodeHex("0c666f6f00000000000000000000000000000000000000000000000000000000"))
        when:
        def act = schnorrkel.derivePublicKeySoft(new Schnorrkel.PublicKey(pub), cc)
        then:
        Hex.encodeHexString(act.getPublicKey()) == "40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a"
    }

    // taken from https://github.com/ChainSafe/go-schnorrkel/blob/d1354d86e41dc066cdf6c755a9d08caffc55b542/vrf_test.go#L90
    def "Test VRF sign and verify"() {
        setup:
        def signTranscript = new TranscriptData("vrf-test".getBytes())
        def verifyTranscript = new TranscriptData("vrf-test".getBytes())

        def keyPair = schnorrkel.generateKeyPair()

        def vrfOutputAndProof = schnorrkel.vrfSign(keyPair, signTranscript)

        when:
        boolean verified = schnorrkel.vrfVerify(keyPair, verifyTranscript, vrfOutputAndProof)

        then:
        verified
    }

    // translated from https://github.com/ChainSafe/go-schnorrkel/blob/d1354d86e41dc066cdf6c755a9d08caffc55b542/vrf_test.go#L172
    def "Test VRF verify from Rust"() {
        setup:
        byte[] pubKeyBytes = new byte[]{-64, 42, 72, -70, 20, 11, 83, -106, -11, 69, -88, -34, 22, -90, -89, 95, 125, -8, -72, 67, -59, 10, -95, 107, -51, 116, -113, -92, -113, 127, -90, 84}
        Schnorrkel.PublicKey pubKey = new Schnorrkel.PublicKey(pubKeyBytes)

        TranscriptData transcript = new TranscriptData("SigningContext".getBytes())
        transcript.appendMessage("", "yo!")
        transcript.appendMessage("sign-bytes", "meow")

        byte[] outputBytes = new byte[] {0, 91, 50, 25, -42, 94, 119, 36, 71, -40, 33, -104, 85, -72, 34, 120, 61, -95, -92, -33, 76, 53, 40, -10, 76, 38, -21, -52, 43, 31, -77, 28}

        byte[] cbytes = new byte[] {120, 23, -21, -97, 115, 122, -49, -50, 123, -24, 75, -13, 115, -1, -125, -75, -37, -15, -56, -50, 21, 22, -18, 16, 68, 49, 86, 99, 76, -117, 39, 0}
        byte[] sbytes = new byte[] {102, 106, -75, -120, 97, -115, -69, 1, -22, -73, -15, 28, 27, -27, -123, 8, 32, -10, -11, -50, -57, -114, -122, 124, -30, -39, 95, 30, -80, -10, 5, 3}
        byte[] proofBytes = new byte[cbytes.length + sbytes.length]
        System.arraycopy(cbytes, 0, proofBytes, 0, cbytes.length)
        System.arraycopy(sbytes, 0, proofBytes, cbytes.length, sbytes.length)

        when:
        boolean verified = schnorrkel.vrfVerify(pubKey, transcript, VrfOutputAndProof.wrap(outputBytes, proofBytes))

        then:
        verified
    }

    // NOTE: This test is currently only a sanity check against trivially false positives
    // translated from https://github.com/ChainSafe/go-schnorrkel/blob/d1354d86e41dc066cdf6c755a9d08caffc55b542/vrf_test.go#L149
    def "Test VRF verify invalid proof fails"() {
        setup:
        def transcript = new TranscriptData("vrf-test".getBytes())
        // Ideally, we'd want this test case to corroborate that "choosing any other than the right scalar would invalidate the proof",
        // i.e. we'd only want to change one of the scalars in the proof.
        // But since we don't have that granularity on our Java side, for now,
        // I've hardcoded this "fake proof", generated from another secret key and another scalar picked at random.
        def invalidProof = new byte[]{117, 87, 1, 77, 44, 43, -13, 116, 47, 125, -44, 124, 47, -113, 46, -126, -76, 68, 46, -11, 42, 64, 7, 43, -121, 107, -18, 123, 19, 66, 115, 7, 107, -104, 95, 62, 4, -100, 111, -23, 79, 56, 108, 113, -127, -85, -38, -35, -33, -97, -43, 85, 52, 106, 71, -53, 11, 81, 96, 35, -80, -119, -14, 1}

        def keyPair = schnorrkel.generateKeyPair()
        def vrfOutputAndProof = schnorrkel.vrfSign(keyPair, transcript)

        when:
        def verifiedValidProof = schnorrkel.vrfVerify(keyPair, transcript, vrfOutputAndProof)

        then:
        verifiedValidProof

        when:
        def verifiedInvalidProof = schnorrkel.vrfVerify(keyPair, transcript, VrfOutputAndProof.wrap(vrfOutputAndProof.getOutput(), invalidProof))

        then:
        !verifiedInvalidProof
    }
}
