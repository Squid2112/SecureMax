package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 * @author Jeff L Greenwell
 * @version 1.0
 */

import java.io.UnsupportedEncodingException;
import java.io.ByteArrayOutputStream;
import com.thixo.security.securemax.smErrors;

public class smCipher {
	private static smCipherKey key = new smCipherKey();
	public boolean isError;
	public String ErrorReason;
	public smErrors Errors;

	public smCipher() {
		this.Errors = new smErrors();
		if (!this.key.isKeySet)
			this.key.Reset();
	}

	public static void main(String args[]) {
		smCipher test = new smCipher();
		byte[] crypt;
		byte[] drypt;

		try {
			String tStr = new String(
					"This is a really good test of this stuff, but I would like to also try this with some binary data");
			crypt = test.EncipherData(tStr.getBytes("UTF-8"));
			drypt = test.DecipherData(crypt);
			String aTest = new String(drypt, "UTF-8");
			System.out.println(new String(crypt));
			System.out.println(com.recruitmax.security.securemax.v1_0.smUtils.Trim00(aTest));
		} catch (UnsupportedEncodingException e) {
			System.out.println("ERROR");
		}
	}

	private long[] Encipher(long p1, long p2) {
		long[] t = new long[3];
		t[0] = 1; // error flag
		t[1] = p1 & 0xFFFFFFFFL;
		t[2] = p2 & 0xFFFFFFFFL;
		long delta = 0x9E3779B9L;
		long sum = 0;
		int n = 32;

		while (n-- > 0) {
			t[1] += ((t[2] << 4) ^ t[2] >>> 5) + (t[2] ^ (sum + this.key.keyBlock[((int) (sum & 3))]));
			t[1] &= 0xFFFFFFFFL;
			sum += delta;
			t[2] += ((t[1] << 4) ^ t[1] >>> 5) + (t[1] ^ (sum + this.key.keyBlock[((int) (sum >>> 11 & 3))]));
			t[2] &= 0xFFFFFFFFL;
		}
		return (t);
	}

	private long[] Decipher(long p1, long p2) {
		long[] t = new long[3];
		t[0] = 1; // error flag
		t[1] = p1 & 0xFFFFFFFFL;
		t[2] = p2 & 0xFFFFFFFFL;
		long sum = 0xC6EF3720L;
		long delta = 0x9E3779B9L;
		int n = 32;

		while (n-- > 0) {
			t[2] -= ((t[1] << 4) ^ t[1] >>> 5) + (t[1] ^ (sum + this.key.keyBlock[((int) (sum >>> 11 & 3))]));
			t[2] &= 0xFFFFFFFFL;
			sum -= delta;
			t[1] -= ((t[2] << 4) ^ t[2] >>> 5) + (t[2] ^ (sum + this.key.keyBlock[((int) (sum & 3))]));
			t[1] &= 0xFFFFFFFFL;
		}
		return (t);
	}

	private byte[] EncipherData(byte[] inData) {
		int i, j;
		ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		int dataByteLength = inData.length + (((inData.length % 8) > 0) ? 8 - (inData.length % 8) : 0);
		byte[] dataBytes = new byte[dataByteLength];
		java.lang.System.arraycopy(inData, 0, dataBytes, 0, inData.length);
		for (i = inData.length; i < dataByteLength; i++)
			dataBytes[i] = 0x00;

		long[] res = new long[3];
		long p1 = 0, p2 = 0;
		i = 0;
		j = 0;

		while (i < dataByteLength) {
			p1 = dataBytes[i++];
			p1 |= dataBytes[i++] << 8;
			p1 |= dataBytes[i++] << 16;
			p1 |= dataBytes[i++] << 24;
			p1 &= 0xFFFFFFFFL;
			p2 = dataBytes[i++];
			p2 |= dataBytes[i++] << 8;
			p2 |= dataBytes[i++] << 16;
			p2 |= dataBytes[i++] << 24;
			p2 &= 0xFFFFFFFFL;
			res = Encipher(p1, p2);

			for (j = 0; j < 4; j++)
				outBytes.write((byte) ((res[1] >>> (j * 8)) & 0xFFL));
			for (j = 0; j < 4; j++)
				outBytes.write((byte) ((res[2] >>> (j * 8)) & 0xFFL));
			p1 = 0;
			p2 = 0;
			res = null;
		}
		return (outBytes.toByteArray());
	}

	private byte[] DecipherData(byte[] inData) {
		ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
		long[] res = new long[3];
		int z = 0, r, j;
		long t, p1, p2, k;

		while (z < inData.length) {
			p1 = 0;
			for (j = 0; j < 4; j++) {
				k = inData[z++] & 0xFFL;
				p1 |= (k << (j * 8));
				p1 &= 0xFFFFFFFFL;
			}
			p2 = 0;
			for (j = 0; j < 4; j++) {
				k = inData[z++] & 0xFFL;
				p2 |= (k << (j * 8));
				p2 &= 0xFFFFFFFFL;
			}
			res = Decipher(p1, p2);

			if (res[0] != 0) {
				for (r = 0; r < 4; r++) {
					t = (res[1] >>> (r * 8)) & 0xFFL;
					outBytes.write((byte) t);
				}
				for (r = 0; r < 4; r++) {
					t = (res[2] >>> (r * 8)) & 0xFFL;
					outBytes.write((byte) t);
				}
			}
		}
		return (outBytes.toByteArray());
	}

}
