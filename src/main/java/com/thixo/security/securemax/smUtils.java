package com.thixo.security.securemax;

/**
 * <p>
 * Title: Squid Security Systems
 * </p>
 * 
 * @version 1.0
 */

public class smUtils {

	private smUtils() {
		// Private constructor to prevent instantiation
	}

	public static String Trim00(String inString) {
		if (inString == null || inString.isEmpty()) {
			return inString;
		}

		int i = inString.length() - 1;
		while (i >= 0 && inString.charAt(i) == 0x00) {
			i--;
		}

		return inString.substring(0, i + 1);
	}

	public static byte[] Trim00(byte[] inData) {
		if (inData == null || inData.length == 0) {
			return inData;
		}

		int i = inData.length - 1;
		while (i >= 0 && inData[i] == 0x00) {
			i--;
		}

		byte[] outBytes = new byte[i + 1];
		System.arraycopy(inData, 0, outBytes, 0, i + 1);

		return outBytes;
	}
}
