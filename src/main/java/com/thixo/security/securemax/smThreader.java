package com.thixo.security.securemax;

import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.io.UnsupportedEncodingException;

public class smThreader {

	private final SecureRandom oRandom;
	private String smEncodingType;
	private final smHexTrig HexTrig;

	public smThreader() {
		this.oRandom = new SecureRandom();
		this.oRandom.setSeed(System.currentTimeMillis());
		this.smEncodingType = StandardCharsets.UTF_8.name();
		this.HexTrig = new smHexTrig();
	}

	public static void main(String[] args) {
		smThreader tThread = new smThreader();
		smHexTrig tHT = new smHexTrig();

		byte[] enT = tThread.enthread("Brandon".getBytes(), "Rice".getBytes());
		byte[][] deT = tThread.dethread(enT);

		System.out.println("Raw: " + new String(enT));
		System.out.println("Threaded: " + tHT.encode(enT));
		System.out.println("     nib: " + new String(deT[0]));
		System.out.println("    data: " + new String(deT[1]));
	}

	public byte[] enthread(byte[] inNib, byte[] inData) {
		if (inNib.length > inData.length) {
			byte[] tmp = inNib;
			inNib = inData;
			inData = tmp;
		}

		int nibLen = inNib.length;
		int totalLen = nibLen + inData.length + 6;
		byte[] outData = new byte[totalLen];
		byte rNib = (byte) oRandom.nextInt(16);
		byte zOrder = (byte) oRandom.nextInt(16);

		outData[0] = rNib;
		outData[1] = (byte) (zOrder ^ rNib);

		for (int i = 0, j = 6; i < nibLen; i++, j += 2) {
			byte tk, td;
			switch (i % 4) {
				case 0 -> {
					tk = (byte) (((inNib[i] & 126) | (inData[i] & 129)) ^ rNib);
					td = (byte) (((inData[i] & 126) | (inNib[i] & 129)) ^ rNib);
				}
				case 1 -> {
					tk = (byte) (((inNib[i] & 189) | (inData[i] & 66)) ^ rNib);
					td = (byte) (((inData[i] & 189) | (inNib[i] & 66)) ^ rNib);
				}
				case 2 -> {
					tk = (byte) (((inNib[i] & 219) | (inData[i] & 36)) ^ rNib);
					td = (byte) (((inData[i] & 219) | (inNib[i] & 36)) ^ rNib);
				}
				case 3 -> {
					tk = (byte) (((inNib[i] & 231) | (inData[i] & 24)) ^ rNib);
					td = (byte) (((inData[i] & 231) | (inNib[i] & 24)) ^ rNib);
				}
				default -> throw new IllegalStateException("Unexpected value: " + (i % 4));
			}
			outData[j] = tk;
			outData[j + 1] = td;
		}

		System.arraycopy(inData, nibLen, outData, nibLen + 6, inData.length - nibLen);

		for (int i = 5; i > 1; i--) {
			outData[i] = (byte) (nibLen ^ rNib);
			nibLen >>= 8;
		}

		return outData;
	}

	public byte[][] dethread(byte[] inData) {
		byte rNib = inData[0];
		long nibLen = ((inData[2] ^ rNib) << 24) |
				((inData[3] ^ rNib) << 16) |
				((inData[4] ^ rNib) << 8) |
				(inData[5] ^ rNib);
		int dataLen = inData.length - 6 - (int) nibLen;
		boolean zOrder = nibLen > dataLen;

		byte[][] outData = new byte[2][];
		outData[0] = new byte[(int) nibLen];
		outData[1] = new byte[dataLen];

		for (int i = 6, j = 0; j < Math.min(nibLen, dataLen); i += 2, j++) {
			byte tk, td;
			switch (j % 4) {
				case 0 -> {
					tk = (byte) (((inData[i] & 126) | (inData[i + 1] & 129)) ^ rNib);
					td = (byte) (((inData[i + 1] & 126) | (inData[i] & 129)) ^ rNib);
				}
				case 1 -> {
					tk = (byte) (((inData[i] & 189) | (inData[i + 1] & 66)) ^ rNib);
					td = (byte) (((inData[i + 1] & 189) | (inData[i] & 66)) ^ rNib);
				}
				case 2 -> {
					tk = (byte) (((inData[i] & 219) | (inData[i + 1] & 36)) ^ rNib);
					td = (byte) (((inData[i + 1] & 219) | (inData[i] & 36)) ^ rNib);
				}
				case 3 -> {
					tk = (byte) (((inData[i] & 231) | (inData[i + 1] & 24)) ^ rNib);
					td = (byte) (((inData[i + 1] & 231) | (inData[i] & 24)) ^ rNib);
				}
				default -> throw new IllegalStateException("Unexpected value: " + (j % 4));
			}
			outData[0][j] = zOrder ? td : tk;
			outData[1][j] = zOrder ? tk : td;
		}

		System.arraycopy(inData, (int) (Math.min(nibLen, dataLen) + 6), outData[zOrder ? 0 : 1],
				(int) Math.min(nibLen, dataLen),
				(int) (Math.max(nibLen, dataLen) - Math.min(nibLen, dataLen)));

		return outData;
	}

	public String smEnthread(String key, String data) {
		try {
			byte[] utf8Key = key.getBytes(smEncodingType);
			byte[] utf8Data = data.getBytes(smEncodingType);
			byte[] threaded = enthread(utf8Key, utf8Data);
			return HexTrig.encode(threaded);
		} catch (UnsupportedEncodingException e) {
			return "ERROR: Unsupported Encoding [" + smEncodingType + "]";
		}
	}

	public String[] smDethread(String data) {
		String decodedString = HexTrig.decode(data);
		byte[] tRaw = decodedString.getBytes(StandardCharsets.UTF_8);
		byte[][] getData = dethread(tRaw);
		return new String[] { new String(getData[0], StandardCharsets.UTF_8),
				new String(getData[1], StandardCharsets.UTF_8) };
	}

	public void setEncoding(String encType) {
		this.smEncodingType = encType;
	}

	public String getEncoding() {
		return this.smEncodingType;
	}
}
