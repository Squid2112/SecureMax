package com.thixo.security.securemax;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * <p>
 * Title: Squid Security Systems
 * </p>
 * 
 * @author Jeff L Greenwell
 * @version 1.0
 */

public class smHexTrig {

	private String smEncodingType;
	public boolean isError;
	public String errorReason;

	public smHexTrig() {
		this.isError = false;
		this.errorReason = "No Error";
		this.smEncodingType = StandardCharsets.UTF_8.name();
	}

	public static void main(String[] args) {
		smHexTrig htTest = new smHexTrig();
		String encString = htTest.encode("This should be a pretty good test of smHexTrig");

		System.out.println(encString);
		encString += "123456";
		String decString = htTest.decode(encString);
		if (htTest.isError) {
			System.out.println(htTest.errorReason);
		} else {
			System.out.println(decString);
		}
	}

	public String encode(byte[] inData) {
		int dataByteLength = (inData.length + 3) & ~3; // Ensure length is a multiple of 4
		byte[] dataBytes = Arrays.copyOf(inData, dataByteLength);

		StringBuilder outData = new StringBuilder();
		for (int i = 0; i < dataBytes.length; i += 4) {
			long t = 0;
			for (int j = 0; j < 4; j++) {
				t <<= 8;
				t |= (dataBytes[i + j] & 0xFFL);
			}
			String t36 = Long.toString(t, 36).toUpperCase();
			while (t36.length() < 6) {
				t36 = '0' + t36;
			}
			outData.append(t36);
		}
		return outData.toString();
	}

	public String encode(String inData) {
		try {
			return encode(inData.getBytes(smEncodingType));
		} catch (UnsupportedEncodingException e) {
			isError = true;
			errorReason = "Unsupported Encoding: " + smEncodingType;
			return "";
		}
	}

	public String decode(String inData) {
		if (inData.length() % 6 != 0) {
			isError = true;
			errorReason = "Invalid Hexatrigesimal Encoding";
			return "";
		}

		byte[] outData = new byte[(inData.length() / 6) * 4];
		int j = 0;

		for (int i = 0; i < inData.length(); i += 6) {
			long t = Long.parseLong(inData.substring(i, i + 6), 36);
			outData[j++] = (byte) (t >>> 24);
			outData[j++] = (byte) (t >>> 16);
			outData[j++] = (byte) (t >>> 8);
			outData[j++] = (byte) t;
		}
		
		return new String(smUtils.Trim00(outData), StandardCharsets.UTF_8);
	}

	public void setEncoding(String encType) {
		this.smEncodingType = encType;
	}

	public String getEncoding() {
		return this.smEncodingType;
	}
}
