package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 * @author Jeff L Greenwell
 * @version 1.0
 */

import java.io.UnsupportedEncodingException;
import com.thixo.security.securemax.smUtils;

public class smHexTrig {

	private String smEncodingType;
	public boolean isError;
	public String errorReason;

	public smHexTrig() {
		this.isError = false;
		this.errorReason = new String("No Error");
		this.smEncodingType = new String("UTF-8");
	}

	public static void main(String args[]) {
		smHexTrig htTest = new smHexTrig();
		String encString = new String("");

		System.out.println(htTest.encode("This should be a pretty good test of smHexTrig"));
		encString = htTest.encode("This should be a pretty good test of smHexTrig");
		encString += "123456";
		String decString = new String(htTest.decode(encString));
		if (htTest.isError)
			System.out.println(htTest.errorReason);
		else
			System.out.println(decString);
	}

	public String encode(byte[] inData) {
		int i, j;
		long t;
		String outData = new String("");
		String t36 = new String("");

		int dataByteLength = inData.length + (((inData.length % 4) > 0) ? 4 - (inData.length % 4) : 0);
		byte[] dataBytes = new byte[dataByteLength];
		java.lang.System.arraycopy(inData, 0, dataBytes, 0, inData.length);
		for (i = inData.length; i < dataByteLength; i++)
			dataBytes[i] = 0x00;

		for (i = 0; i < dataBytes.length; i += 4) {
			t = 0;
			t36 = "";
			for (j = 0; j < 4; j++) {
				t <<= 8;
				t |= (long) (dataBytes[i + j] & 0x0FFFFFFFFL);
			}
			t36 += (Long.toString((long) (t & 0x0FFFFFFFFL), 36).toUpperCase());
			while (t36.length() < 6)
				t36 = '0' + t36;
			outData += t36;
		}
		return (outData);
	}

	public String encode(String inData) {
		String outData;
		try {
			outData = new String(encode(inData.getBytes(this.smEncodingType)));
		} catch (UnsupportedEncodingException e) {
			return ("");
		}
		return (outData);
	}

	public byte[] decode(String inData) {
		byte[] outData = new byte[(inData.length() / 6) * 4];

		if ((inData.length() % 6) != 0) {
			this.isError = true;
			this.errorReason = "Invalid Hexatrigesimal Encoding";
			return (outData);
		}

		int i, z, j = 0;
		long t;

		for (i = 0; i < inData.length(); i += 6) {
			t = Long.parseLong(inData.substring(i, i + 6), 36) & 0x0FFFFFFFFL;
			outData[j++] = (byte) ((t >>> 24) & 0xFFL);
			outData[j++] = (byte) ((t >>> 16) & 0xFFL);
			outData[j++] = (byte) ((t >>> 8) & 0xFFL);
			outData[j++] = (byte) (t & 0xFFL);
		}
		return (com.recruitmax.security.securemax.v1_0.smUtils.Trim00(outData));
	}

	public void setEncoding(String encType) {
		this.smEncodingType = encType;
	}

	public String getEncoding() {
		return (this.smEncodingType);
	}
}
