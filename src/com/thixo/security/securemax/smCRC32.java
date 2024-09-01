package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 * @author Jeff L Greenwell
 * @version 1.0
 */

import java.util.zip.CRC32;
import java.io.UnsupportedEncodingException;
import com.thixo.security.securemax.smBase64;

public class smCRC32 {
	private CRC32 intCRC32;
	private String smEncodingType = new String("UTF-8");

	public smCRC32() {
		this.intCRC32 = new CRC32();
	}

	public static void main(String args[]) {
		smCRC32 test = new smCRC32();

		System.out.println(test.toInt("this is also another test"));
		System.out.println(test.toBase64("this is a base64 test with a lot more text"));
	}

	public long toInt(byte[] inData) {
		this.intCRC32.reset();
		this.intCRC32.update(inData);
		return (this.intCRC32.getValue());
	}

	public long toInt(String inData) {
		this.intCRC32.reset();
		try {
			this.intCRC32.update(inData.getBytes(this.smEncodingType));
		} catch (UnsupportedEncodingException e) {
			return (0L);
		}
		return (this.intCRC32.getValue());
	}

	public String toHexTrig(byte[] inData) {
		this.intCRC32.reset();
		this.intCRC32.update(inData);
		int tRaw = (int) (this.intCRC32.getValue() & 0xFFFFFFFFL);
		String tCRC;
		if (tRaw < 0)
			tRaw = (tRaw * -1) + 1;
		tCRC = new String(Integer.toString(tRaw, 36).toUpperCase());
		while (tCRC.length() < 6)
			tCRC = '0' + tCRC;
		return (tCRC);
	}

	public String toHexTrig(String inData) {
		this.intCRC32.reset();
		try {
			return (toHexTrig(inData.getBytes(this.smEncodingType)));
		} catch (UnsupportedEncodingException e) {
			return ("");
		}
	}

	public String toHex(byte[] inData) {
		this.intCRC32.reset();
		this.intCRC32.update(inData);
		int tRaw = (int) (this.intCRC32.getValue() & 0xFFFFFFFFL);
		String tCRC;
		if (tRaw < 0)
			tRaw = (tRaw * -1) + 1;
		tCRC = Integer.toString(tRaw, 16).toUpperCase();
		while (tCRC.length() < 8)
			tCRC = '0' + tCRC;
		return (tCRC);
	}

	public String toHex(String inData) {
		this.intCRC32.reset();
		try {
			return (toHex(inData.getBytes(this.smEncodingType)));
		} catch (UnsupportedEncodingException e) {
			return ("");
		}
	}

	public String toBase64(byte[] inData) {
		this.intCRC32.reset();
		this.intCRC32.update(inData);
		int tRaw = (int) (this.intCRC32.getValue() & 0xFFFFFFFFL);
		smBase64 b64 = new smBase64();
		return (b64.encode(Integer.toString(tRaw)));
	}

	public String toBase64(String inData) {
		this.intCRC32.reset();
		try {
			return (toBase64(inData.getBytes(this.smEncodingType)));
		} catch (UnsupportedEncodingException e) {
			return ("");
		}
	}

	public void setEncoding(String encType) {
		this.smEncodingType = encType;
	}

	public String getEncoding() {
		return (this.smEncodingType);
	}
}
