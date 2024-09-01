package com.thixo.security.securemax;

import java.security.SecureRandom;

/**
 * <p>
 * Title: Squid Security Systems
 * </p>
 * 
 * @version 1.0
 */

public class smCipherKey {

	private final SecureRandom oRandom;
	protected final long[] keyBlock;
	protected boolean isKeySet = false;

	public smCipherKey() {
		this.oRandom = new SecureRandom();
		this.keyBlock = new long[4];
		Reset();
	}

	public smCipherKey(String keyString) {
		this.oRandom = new SecureRandom();
		this.keyBlock = new long[4];
		Reset(keyString);
	}

	public void Reset() {
		this.oRandom.setSeed(System.currentTimeMillis());
		BuildKey();
	}

	public void Reset(String keyString) {
		BuildKey(keyString);
	}

	private void BuildKey() {
		for (int i = 0; i < 4; i++) {
			this.keyBlock[i] = this.oRandom.nextInt() & 0xFFFFFFFFL; // Ensures 32-bit values
		}
		this.isKeySet = true;
	}

	private void BuildKey(String keyString) {
		if (keyString.length() < 16) {
			keyString = String.format("%-16s", keyString).replace(' ', keyString.charAt(0));
		}

		for (int i = 0; i < 4; i++) {
			this.keyBlock[i] = 0L;
			for (int j = 0; j < 4; j++) {
				this.keyBlock[i] |= (long) (keyString.charAt(i * 4 + j) & 0xFF) << (j * 8);
			}
		}
		this.isKeySet = true;
	}
}
