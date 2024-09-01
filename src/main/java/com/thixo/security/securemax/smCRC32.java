package com.thixo.security.securemax;

import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

/**
 * <p>
 * Title: Squid Security Systems
 * </p>
 * 
 * @author Jeff L Greenwell
 * @version 1.0
 */

public class smCRC32 {
	private final CRC32 intCRC32;
	private String smEncodingType;

	public smCRC32() {
		this.intCRC32 = new CRC32();
		this.smEncodingType = StandardCharsets.UTF_8.name();
	}

	public long toInt(byte[] inData) {
		intCRC32.reset();
		intCRC32.update(inData);
		return intCRC32.getValue();
	}

	public long toInt(String inData) {
		intCRC32.reset();
		intCRC32.update(getBytes(inData));
		return intCRC32.getValue();
	}

	public String toHexTrig(byte[] inData) {
		intCRC32.reset();
		intCRC32.update(inData);
		long tRaw = intCRC32.getValue() & 0xFFFFFFFFL; // Convert to unsigned 32-bit value
		return padLeft(Long.toString(tRaw, 36).toUpperCase(), 6, '0');
	}

	public String toHexTrig(String inData) {
		return toHexTrig(getBytes(inData));
	}

	public String toHex(byte[] inData) {
		intCRC32.reset();
		intCRC32.update(inData);
		int tRaw = (int) intCRC32.getValue();
		return padLeft(Integer.toHexString(tRaw).toUpperCase(), 8, '0');
	}

	public String toHex(String inData) {
		return toHex(getBytes(inData));
	}

	public String toBase64(byte[] inData) {
		intCRC32.reset();
		intCRC32.update(inData);
		int tRaw = (int) intCRC32.getValue();
		return smBase64.encode(Integer.toString(tRaw));
	}

	public String toBase64(String inData) {
		return toBase64(getBytes(inData));
	}

	public void setEncoding(String encType) {
		this.smEncodingType = encType;
	}

	public String getEncoding() {
		return this.smEncodingType;
	}

	private byte[] getBytes(String inData) {
		return inData.getBytes(StandardCharsets.UTF_8);
	}

	private String padLeft(String input, int length, char padChar) {
		if (input.length() >= length)
			return input;
		StringBuilder sb = new StringBuilder(length);
		while (sb.length() < length - input.length()) {
			sb.append(padChar);
		}
		sb.append(input);
		return sb.toString();
	}

}
