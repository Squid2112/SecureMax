package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 *
 * @author Jeff L Greenwell
 * @version 1.0
 */

import java.util.regex.*;
import java.io.UnsupportedEncodingException;
import com.thixo.security.securemax.smBase64;
import com.thixo.security.securemax.smCRC32;
import com.thixo.security.securemax.smHexTrig;
import com.thixo.security.securemax.smUtils;
import com.thixo.security.securemax.smThreader;

public class smPageProcessor {
	private static final Pattern PageLinkPattern = Pattern.compile(
			"(\"|')([\\S]*)\\.cfm\\?([^/!\"']*?)\\1(?![\\s]*\\+)",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private smThreader Threader;
	private smCRC32 CRC32;
	private smHexTrig HexTrig;

	public smPageProcessor() {
		this.Threader = new smThreader();
		this.CRC32 = new smCRC32();
		this.HexTrig = new smHexTrig();
		new smBase64();
	}

	public static void main(String args[]) {
		smPageProcessor pTest = new smPageProcessor();
		String encData = new String(
				pTest.encodeParams("test.me.com", "\"orderaddupdate.cfm?szParam1=Values1&szParam2=Values2\""));
		String decData = new String(
				pTest.DecodeParams("test.me.comorderaddupdate.cfm", encData.substring(0, encData.length() - 1)));

		System.out.println(encData);
		System.out.println(decData);

	}

	public String encodeParams(String serverName, String inData) {
		Matcher linkMatcher = PageLinkPattern.matcher(inData);
		StringBuffer outData = new StringBuffer("");
		String finds;
		String page;
		String params;
		String rString;
		String delim;
		String serverPage;
		String threadData, threadCRC;
		byte[] tData;

		while (linkMatcher.find()) {
			finds = linkMatcher.group();
			page = new String(finds.substring(1, finds.indexOf("?")));
			delim = new String(finds.substring(0, 1));
			params = new String(finds.substring(finds.indexOf("?") + 1, finds.length() - 1));
			rString = new String(delim + page + "?/");
			serverPage = serverName + page;
			tData = this.Threader.enthread(serverPage.getBytes(), params.getBytes());
			threadCRC = new String(this.CRC32.toHexTrig(new String(tData)));
			threadData = new String(this.HexTrig.encode(this.Threader.enthread(threadCRC.getBytes(), tData)));
			rString = new String(rString + threadData + delim);
			linkMatcher.appendReplacement(outData, rString);
		}
		linkMatcher.appendTail(outData);
		return (outData.toString());
	}

	public String DecodeParams(String serverPage, String inData) {
		String outData = new String("");
		byte[][] threadData;
		int curIndex = inData.indexOf("/", 0);
		int idx = 0;
		String curParams;
		String enCRC32;
		byte[] enData;
		String enServerPage;
		String threadCRC;
		String enParams;

		while (curIndex < inData.length()) {
			idx = (inData.indexOf("/", curIndex) == inData.lastIndexOf("/") ? inData.length()
					: inData.indexOf("/", curIndex + 1));
			curParams = new String(inData.substring(curIndex + 1, idx));
			curIndex = idx;
			threadData = this.Threader.dethread(this.HexTrig.decode(curParams));
			enCRC32 = new String(threadData[0]);
			enData = threadData[1];
			threadCRC = new String(this.CRC32.toHexTrig(new String(enData)));
			if (!enCRC32.equals(threadCRC))
				return (new String(""));
			threadData = this.Threader.dethread(enData);
			enServerPage = new String(threadData[0]);
			if (!enServerPage.equalsIgnoreCase(serverPage))
				return (new String(""));
			enParams = new String(threadData[1]);
			outData += enParams;
			if (curIndex < inData.length())
				outData += "&";
		}
		return (outData);
	}
}
