package com.thixo.security.securemax;

import java.security.SecureRandom;
import java.io.UnsupportedEncodingException;

/**
 * <p>
 * Title: Squid Security Systems
 * </p>
 * 
 * @author Jeff L Greenwell
 * @version 1.0
 */

public class smThreader {

	private SecureRandom oRandom;
	private String smEncodingType = new String("UTF-8");
	private smHexTrig HexTrig = new smHexTrig();

	public smThreader() {
		this.oRandom = new SecureRandom();
		this.oRandom.setSeed(java.lang.System.currentTimeMillis());
	}

	public static void main(String args[]) {
		smThreader tThread = new smThreader();
		smHexTrig tHT = new smHexTrig();

		byte[] enT;
		byte[][] deT;

		enT = tThread.enthread("Brandon".getBytes(), "Rice".getBytes());
		deT = tThread.dethread(enT);
		System.out.println("Raw: " + new String(enT));
		System.out.println("Threaded: " + new String(tHT.encode(enT)));
		System.out.println("     nib: " + new String(deT[0]));
		System.out.println("    data: " + new String(deT[1]));
	}

	public byte[] enthread(byte[] inNib, byte[] inData) {
		int i, ii, j;
		byte tk = 0x00, td = 0x00;
		byte[] outData = new byte[(inNib.length + inData.length + 6)];
		long nibLen = (long) (inNib.length & 0x0FFFF);
		byte rNib = (byte) this.oRandom.nextInt(16);
		byte zOrder = (byte) this.oRandom.nextInt(16);
		byte[] tmp;

		if (inNib.length > inData.length) {
			tmp = inNib;
			inNib = inData;
			inData = tmp;
		}

		for (i = 0, ii = 6; i < inNib.length; i++, ii += 2) {
			switch (i % 4) {
				case 0:
					tk = (byte) (((inNib[i] & 126) | (inData[i] & 129)) ^ rNib);
					td = (byte) (((inData[i] & 126) | (inNib[i] & 129)) ^ rNib);
					break;

				case 1:
					tk = (byte) (((inNib[i] & 189) | (inData[i] & 66)) ^ rNib);
					td = (byte) (((inData[i] & 189) | (inNib[i] & 66)) ^ rNib);
					break;

				case 2:
					tk = (byte) (((inNib[i] & 219) | (inData[i] & 36)) ^ rNib);
					td = (byte) (((inData[i] & 219) | (inNib[i] & 36)) ^ rNib);
					break;

				case 3:
					tk = (byte) (((inNib[i] & 231) | (inData[i] & 24)) ^ rNib);
					td = (byte) (((inData[i] & 231) | (inNib[i] & 24)) ^ rNib);
					break;
			}
			outData[ii] = tk;
			outData[ii + 1] = td;
		}
		for (j = i; j < inData.length; j++)
			outData[ii++] = (byte) (inData[j] ^ rNib);
		for (i = 5; i > 1; i--) {
			outData[i] = (byte) (nibLen ^ rNib);
			nibLen >>= 8;
		}

		outData[0] = rNib;
		outData[1] = (byte) (zOrder ^ rNib);
		return (outData);
	}

	public byte[][] dethread(byte[] inData) {
		int i, ii, j;
		byte[][] outData = new byte[2][];
		byte tk = 0x00, td = 0x00;
		byte rNib = inData[0];
		long nibLen = 0L;

		nibLen += ((inData[2] ^ rNib) << 24);
		nibLen += ((inData[3] ^ rNib) << 16);
		nibLen += ((inData[4] ^ rNib) << 8);
		nibLen += (inData[5] ^ rNib);
		int dataLen = (int) ((inData.length - 6) - nibLen);
		boolean zOrder = (nibLen > dataLen);

		outData[0] = new byte[(int) nibLen];
		outData[1] = new byte[(int) dataLen];

		for (i = 6, j = 0; j < ((zOrder) ? dataLen : nibLen); i += 2, j++) {
			switch (j % 4) {
				case 0:
					tk = (byte) (((inData[i] & 126) | (inData[i + 1] & 129)) ^ rNib);
					td = (byte) (((inData[i + 1] & 126) | (inData[i] & 129)) ^ rNib);
					break;

				case 1:
					tk = (byte) (((inData[i] & 189) | (inData[i + 1] & 66)) ^ rNib);
					td = (byte) (((inData[i + 1] & 189) | (inData[i] & 66)) ^ rNib);
					break;

				case 2:
					tk = (byte) (((inData[i] & 219) | (inData[i + 1] & 36)) ^ rNib);
					td = (byte) (((inData[i + 1] & 219) | (inData[i] & 36)) ^ rNib);
					break;

				case 3:
					tk = (byte) (((inData[i] & 231) | (inData[i + 1] & 24)) ^ rNib);
					td = (byte) (((inData[i + 1] & 231) | (inData[i] & 24)) ^ rNib);
					break;
			}

			outData[0][j] = (zOrder) ? td : tk;
			outData[1][j] = (zOrder) ? tk : td;
		}
		for (ii = i; j < ((zOrder) ? nibLen : dataLen); j++, ii++)
			outData[(zOrder) ? 0 : 1][j] = (byte) (inData[ii] ^ rNib);
		return (outData);
	}

	public String smEnthread(String Key, String Data) {
		byte[] utf8Key;
		byte[] utf8Data;
		byte[] Threaded;

		try {
			utf8Key = Key.getBytes(this.smEncodingType);
		} catch (UnsupportedEncodingException e) {
			return ("ERROR: Unsupported Encoding [" + this.smEncodingType + "]");
		}

		try {
			utf8Data = Data.getBytes(this.smEncodingType);
		} catch (UnsupportedEncodingException e) {
			return ("ERROR: Unsupported Encoding [" + this.smEncodingType + "]");
		}
		Threaded = enthread(utf8Key, utf8Data);

		return (new String(this.HexTrig.encode(Threaded)));
	}

	public String[] smDethread(String Data) {
		String[] outData = new String[2];
		byte[][] getData;

		String tRaw = this.HexTrig.decode(Data);
		byte[] tRawBytes = tRaw.getBytes();
		getData = dethread(tRawBytes);
		outData[0] = new String(getData[0]);
		outData[1] = new String(getData[1]);
		return (outData);
	}

	public void setEncoding(String encType) {
		this.smEncodingType = encType;
	}

	public String getEncoding() {
		return (this.smEncodingType);
	}

}
