package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 * @author Jeff L Greenwell
 * @version 1.0
 */

import java.util.zip.Adler32;
import java.io.UnsupportedEncodingException;

public class smAdler32 {

	private static Adler32 intAdler32;
	private String smEncodingType = new String("UTF-8");

	public smAdler32() {
		intAdler32 = new Adler32();
	}

	public long rawAdler32(byte[] inData) {
		intAdler32.update(inData);
		return (intAdler32.getValue());
	}

	public long rawAdler32(String inData) {
		try {
			intAdler32.update(inData.getBytes(this.smEncodingType));
		} catch (UnsupportedEncodingException e) {
			return (0L);
		}
		return (intAdler32.getValue());
	}

	public String hexTrigAdler32(byte[] inData) {
		intAdler32.update(inData);
		int tRaw = (int) (intAdler32.getValue() & 0xFFFFFFFFL);
		String tAdler;
		if (tRaw < 0)
			tRaw = (tRaw * -1) + 1;
		tAdler = Integer.toString(tRaw, 36).toUpperCase();
		while (tAdler.length() < 8)
			tAdler = '0' + tAdler;
		return (tAdler);
	}

	public String hexTrigAdler32(String inData) {
		try {
			return (hexTrigAdler32(inData.getBytes(this.smEncodingType)));
		} catch (UnsupportedEncodingException e) {
			return ("");
		}
	}

	public String hexAdler32(byte[] inData) {
		intAdler32.update(inData);
		int tRaw = (int) (intAdler32.getValue() & 0xFFFFFFFFL);
		String tAdler;
		if (tRaw < 0)
			tRaw = (tRaw * -1) + 1;
		tAdler = Integer.toString(tRaw, 16).toUpperCase();
		while (tAdler.length() < 8)
			tAdler = '0' + tAdler;
		return (tAdler);
	}

	public String hexAdler32(String inData) {
		try {
			return (hexAdler32(inData.getBytes(this.smEncodingType)));
		} catch (UnsupportedEncodingException e) {
			return ("");
		}
	}

	@SuppressWarnings("static-access")
	public String base64Adler32(byte[] inData) {
		intAdler32.update(inData);
		int tRaw = (int) (intAdler32.getValue() & 0xFFFFFFFFL);
		smBase64 b64 = new smBase64();
		return (b64.encode(Integer.toString(tRaw)));
	}

	public String base64Adler32(String inData) {
		try {
			return (base64Adler32(inData.getBytes(this.smEncodingType)));
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
