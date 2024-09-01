package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 * @author Jeff L Greenwell
 * @version 1.0
 */

public class smUtils {
	public smUtils() {
	}

	public static String Trim00(String inString) {
		String outString = "";
		int i = inString.length();
		do {
			i--;
		} while (((int) inString.charAt(i) == 0x00) && (i > 0));
		outString = new String(inString.substring(0, i + 1));
		return (outString);
	}

	public static byte[] Trim00(byte[] inData) {
		int i = inData.length;
		do {
			i--;
		} while ((inData[i] == 0x00) && (i > 0));
		byte[] outBytes = new byte[i + 1];
		java.lang.System.arraycopy(inData, 0, outBytes, 0, i + 1);
		return (outBytes);
	}
}
