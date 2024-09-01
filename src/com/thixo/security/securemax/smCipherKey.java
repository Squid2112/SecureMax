package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 * @author Jeff L Greenwell
 * @version 1.0
 */

import java.security.SecureRandom;

public class smCipherKey {

	private SecureRandom oRandom;
	protected long[] keyBlock;
	protected boolean isKeySet = false;

	public smCipherKey() {
		Reset();
	}

	public smCipherKey(String keyString) {
		Reset(keyString);
	}

	public void Reset() {
		this.oRandom = new SecureRandom();
		this.keyBlock = new long[4];
		this.oRandom.setSeed(java.lang.System.currentTimeMillis());
		this.BuildKey();
		this.isKeySet = true;
		return;
	}

	public void Reset(String keyString) {
		this.keyBlock = new long[4];
		this.BuildKey(keyString);
		this.isKeySet = true;
		return;
	}

	private void BuildKey() {
		int i;
		for (i = 0; i < 4; i++)
			this.keyBlock[i] = this.oRandom.nextInt(32);
		this.isKeySet = true;
		return;
	}

	private void BuildKey(String keyString) {
		int i, j, z = 0;

		while (keyString.length() < 16)
			keyString += keyString;
		for (i = 0; i < 4; i++) {
			this.keyBlock[i] = 0x00000000L;
			for (j = 0; j < 4; j++)
				this.keyBlock[i] |= ((keyString.charAt(z++) & 0xFF) << (j * 8));
		}
		this.isKeySet = true;
		return;
	}

}
