package dev.skidfuscator.obfuscator.transform.impl.string.generator.v3;

import dev.skidfuscator.obfuscator.skidasm.SkidClassNode;
import dev.skidfuscator.obfuscator.skidasm.SkidMethodNode;
import dev.skidfuscator.obfuscator.skidasm.cfg.SkidBlock;
import dev.skidfuscator.obfuscator.util.RandomUtil;
import org.mapleir.ir.code.Expr;

import java.nio.charset.StandardCharsets;

public class PolymorphicEncryptionGeneratorV3 extends AbstractEncryptionGeneratorV3 {
    private final byte[] keys;

    public PolymorphicEncryptionGeneratorV3(byte[] keys) {
        super("Polymorphic Generator");
        this.keys = keys;
    }

    private Expr internalKeys;

    @Override
    public void visitPre(SkidClassNode node) {
        super.visitPre(node);
        this.internalKeys = generateByteArrayGenerator(node, keys);
    }

    @Override
    public Expr encrypt(String input, SkidMethodNode node, SkidBlock block) {
        final byte[] encrypted = input.getBytes(StandardCharsets.UTF_16);

        // Choose a random polymorphic variant per string
        final int variant = RandomUtil.nextInt(3); // 0, 1, 2

        // Apply polymorphic encryption
        switch (variant) {
            case 0: // XOR with key and keys
                encryptVariant0(encrypted, node.getBlockPredicate(block));
                break;
            case 1: // XOR with rotation
                encryptVariant1(encrypted, node.getBlockPredicate(block));
                break;
            case 2: // XOR with addition
                encryptVariant2(encrypted, node.getBlockPredicate(block));
                break;
        }

        return callInjectMethod(
                node.getParent(),
                "decryptor",
                "([B[BII)Ljava/lang/String;",
                generateByteArrayGenerator(node.getParent(), encrypted),
                internalKeys.copy(),
                node.getFlowPredicate().getGetter().get(block),
                new org.mapleir.ir.code.expr.ConstantExpr(variant, org.objectweb.asm.Type.INT_TYPE)
        );
    }

    private void encryptVariant0(byte[] encrypted, int key) {
        final byte[] keyBytes = Integer.toString(key).getBytes();
        for (int i = 0; i < encrypted.length; i++) {
            encrypted[i] ^= keyBytes[i % keyBytes.length];
            encrypted[i] ^= keys[i % keys.length];
        }
    }

    private void encryptVariant1(byte[] encrypted, int key) {
        final byte[] keyBytes = Integer.toString(key).getBytes();
        for (int i = 0; i < encrypted.length; i++) {
            encrypted[i] ^= keyBytes[i % keyBytes.length];
            encrypted[i] ^= keys[i % keys.length];
            encrypted[i] = (byte) ((encrypted[i] << 3) | ((encrypted[i] & 0xFF) >>> 5)); // Rotate left by 3
        }
    }

    private void encryptVariant2(byte[] encrypted, int key) {
        final byte[] keyBytes = Integer.toString(key).getBytes();
        for (int i = 0; i < encrypted.length; i++) {
            encrypted[i] ^= keyBytes[i % keyBytes.length];
            encrypted[i] ^= keys[i % keys.length];
            encrypted[i] += (byte) (key % 256);
        }
    }

    @Override
    public String decrypt(DecryptorDictionary dictionary, int key) {
        final byte[] input = dictionary.get("encrypted");
        final int variant = (int) dictionary.get("variant");

        switch (variant) {
            case 0:
                decryptVariant0(input, key);
                break;
            case 1:
                decryptVariant1(input, key);
                break;
            case 2:
                decryptVariant2(input, key);
                break;
        }

        return new String(input, StandardCharsets.UTF_16);
    }

    private void decryptVariant0(byte[] input, int key) {
        final byte[] keyBytes = Integer.toString(key).getBytes();
        for (int i = 0; i < input.length; i++) {
            input[i] ^= keys[i % keys.length];
            input[i] ^= keyBytes[i % keyBytes.length];
        }
    }

    private void decryptVariant1(byte[] input, int key) {
        final byte[] keyBytes = Integer.toString(key).getBytes();
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) ((input[i] & 0xFF) >>> 3 | (input[i] << 5)); // Rotate right by 3
            input[i] ^= keys[i % keys.length];
            input[i] ^= keyBytes[i % keyBytes.length];
        }
    }

    private void decryptVariant2(byte[] input, int key) {
        final byte[] keyBytes = Integer.toString(key).getBytes();
        for (int i = 0; i < input.length; i++) {
            input[i] -= (byte) (key % 256);
            input[i] ^= keys[i % keys.length];
            input[i] ^= keyBytes[i % keyBytes.length];
        }
    }

    @InjectMethod(value = "decryptor", tags = InjectMethodTag.RANDOM_NAME)
    private static String decryptMeBitch(final byte[] input, final byte[] keys, final int key, final int variant) {
        switch (variant) {
            case 0:
                decryptStaticVariant0(input, keys, key);
                break;
            case 1:
                decryptStaticVariant1(input, keys, key);
                break;
            case 2:
                decryptStaticVariant2(input, keys, key);
                break;
        }

        return new String(input, StandardCharsets.UTF_16);
    }

    private static void decryptStaticVariant0(byte[] input, byte[] keys, int key) {
        final byte[] keyBytes = Integer.toString(key).getBytes();
        for (int i = 0; i < input.length; i++) {
            input[i] ^= keys[i % keys.length];
            input[i] ^= keyBytes[i % keyBytes.length];
        }
    }

    private static void decryptStaticVariant1(byte[] input, byte[] keys, int key) {
        final byte[] keyBytes = Integer.toString(key).getBytes();
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) ((input[i] & 0xFF) >>> 3 | (input[i] << 5)); // Rotate right by 3
            input[i] ^= keys[i % keys.length];
            input[i] ^= keyBytes[i % keyBytes.length];
        }
    }

    private static void decryptStaticVariant2(byte[] input, byte[] keys, int key) {
        final byte[] keyBytes = Integer.toString(key).getBytes();
        for (int i = 0; i < input.length; i++) {
            input[i] -= (byte) (key % 256);
            input[i] ^= keys[i % keys.length];
            input[i] ^= keyBytes[i % keyBytes.length];
        }
    }
}