package com.thixo.security.securemax;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * <p>
 * Title: Squid Security Systems
 * </p>
 * 
 * @version 1.3.2
 * 
 */

public class smCipher {
	private static final smCipherKey key = new smCipherKey();
	public boolean isError;
	public String ErrorReason;
	public smErrors Errors;

	public smCipher() {
		this.Errors = new smErrors();
		if (!key.isKeySet) {
			key.Reset();
		}
	}

	public smCipher getCipher() {
		return this;
	}

	public long[] Encipher(long p1, long p2) {
		long v1 = p1, v2 = p2;
		long delta = 0x9E3779B9L;
		long sum = 0;
		for (int i = 0; i < 32; i++) {
			v1 += ((v2 << 4) ^ (v2 >>> 5)) + (v2 ^ (sum + key.keyBlock[(int) (sum & 3)]));
			v1 &= 0xFFFFFFFFL;
			sum += delta;
			v2 += ((v1 << 4) ^ (v1 >>> 5)) + (v1 ^ (sum + key.keyBlock[(int) ((sum >>> 11) & 3)]));
			v2 &= 0xFFFFFFFFL;
		}
		return new long[] { v1, v2 };
	}

	public long[] Decipher(long p1, long p2) {
		long v1 = p1, v2 = p2;
		long delta = 0x9E3779B9L;
		long sum = 0xC6EF3720L;
		for (int i = 0; i < 32; i++) {
			v2 -= ((v1 << 4) ^ (v1 >>> 5)) + (v1 ^ (sum + key.keyBlock[(int) ((sum >>> 11) & 3)]));
			v2 &= 0xFFFFFFFFL;
			sum -= delta;
			v1 -= ((v2 << 4) ^ (v2 >>> 5)) + (v2 ^ (sum + key.keyBlock[(int) (sum & 3)]));
			v1 &= 0xFFFFFFFFL;
		}
		return new long[] { v1, v2 };
	}

	public byte[] EncipherData(byte[] inData) {
		ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		int dataByteLength = ((inData.length + 7) / 8) * 8; // Ensure data length is a multiple of 8
		byte[] dataBytes = new byte[dataByteLength];
		System.arraycopy(inData, 0, dataBytes, 0, inData.length);

		for (int i = 0; i < dataByteLength; i += 8) {
			long p1 = getLong(dataBytes, i);
			long p2 = getLong(dataBytes, i + 4);
			long[] res = Encipher(p1, p2);
			writeLong(outBytes, res[0]);
			writeLong(outBytes, res[1]);
		}

		return outBytes.toByteArray();
	}

	public byte[] DecipherData(byte[] inData) {
		ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		for (int i = 0; i < inData.length; i += 8) {
			long p1 = getLong(inData, i);
			long p2 = getLong(inData, i + 4);
			long[] res = Decipher(p1, p2);
			writeLong(outBytes, res[0]);
			writeLong(outBytes, res[1]);
		}
		return outBytes.toByteArray();
	}

	private long getLong(byte[] data, int offset) {
		return ((long) data[offset] & 0xFF) |
				(((long) data[offset + 1] & 0xFF) << 8) |
				(((long) data[offset + 2] & 0xFF) << 16) |
				(((long) data[offset + 3] & 0xFF) << 24);
	}

	private void writeLong(ByteArrayOutputStream outBytes, long value) {
		outBytes.write((byte) (value & 0xFF));
		outBytes.write((byte) ((value >> 8) & 0xFF));
		outBytes.write((byte) ((value >> 16) & 0xFF));
		outBytes.write((byte) ((value >> 24) & 0xFF));
	}
}
