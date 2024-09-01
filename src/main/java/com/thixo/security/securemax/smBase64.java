package com.thixo.security.securemax;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Title: Squid Security Systems
 * 
 * @author Jeff L Greenwell
 * @version 1.5.2
 */

public class smBase64 {

	private static final char[] MAP1 = new char[64];
	private static final byte[] MAP2 = new byte[128];

	static {
		int i = 0;
		for (char c = 'A'; c <= 'Z'; c++)
			MAP1[i++] = c;
		for (char c = 'a'; c <= 'z'; c++)
			MAP1[i++] = c;
		for (char c = '0'; c <= '9'; c++)
			MAP1[i++] = c;
		MAP1[i++] = '+';
		MAP1[i] = '/';

		Arrays.fill(MAP2, (byte) -1);
		for (i = 0; i < 64; i++)
			MAP2[MAP1[i]] = (byte) i;
	}

	public static String encode(String s) {
		return new String(encode(s.getBytes(StandardCharsets.UTF_8)));
	}

	public static char[] encode(byte[] in) {
		int iLen = in.length;
		int oLen = ((iLen + 2) / 3) * 4;
		char[] out = new char[oLen];
		int ip = 0, op = 0;

		while (ip < iLen) {
			int i0 = in[ip++] & 0xff;
			int i1 = ip < iLen ? in[ip++] & 0xff : 0;
			int i2 = ip < iLen ? in[ip++] & 0xff : 0;

			out[op++] = MAP1[i0 >>> 2];
			out[op++] = MAP1[((i0 & 3) << 4) | (i1 >>> 4)];
			out[op++] = op < oLen ? MAP1[((i1 & 0xf) << 2) | (i2 >>> 6)] : '=';
			out[op++] = op < oLen ? MAP1[i2 & 0x3F] : '=';
		}
		return out;
	}

	public static String decode(String s) {
		return new String(decode(s.toCharArray()), StandardCharsets.UTF_8);
	}

	public static byte[] decode(char[] in) {
		int iLen = in.length;
		if (iLen % 4 != 0) {
			throw new IllegalArgumentException("Length of Base64 encoded input string is not a multiple of 4.");
		}

		while (iLen > 0 && in[iLen - 1] == '=')
			iLen--;

		int oLen = (iLen * 3) / 4;
		byte[] out = new byte[oLen];
		int ip = 0, op = 0;

		while (ip < iLen) {
			int i0 = in[ip++];
			int i1 = in[ip++];
			int i2 = ip < iLen ? in[ip++] : 'A';
			int i3 = ip < iLen ? in[ip++] : 'A';

			if (i0 > 127 || i1 > 127 || i2 > 127 || i3 > 127 ||
					MAP2[i0] == -1 || MAP2[i1] == -1 || MAP2[i2] == -1 || MAP2[i3] == -1) {
				throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
			}

			int b0 = MAP2[i0];
			int b1 = MAP2[i1];
			int b2 = MAP2[i2];
			int b3 = MAP2[i3];

			out[op++] = (byte) ((b0 << 2) | (b1 >>> 4));
			if (op < oLen)
				out[op++] = (byte) ((b1 & 0xf) << 4 | (b2 >>> 2));
			if (op < oLen)
				out[op++] = (byte) ((b2 & 3) << 6 | b3);
		}
		return out;
	}
}
