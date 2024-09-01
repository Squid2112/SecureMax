package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 * @author Jeff L Greenwell
 * @version 1.0
 */

import java.io.*;
import java.net.*;
import java.util.regex.*;

public class smPageFilter {
	private static final Pattern PageLinkPattern = Pattern.compile(
			"(\"|')([\\S]*)\\.cfm\\?([^/!\"']*?)\\1(?![\\s]*\\+)",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern FormPattern = Pattern.compile("<(form)[^>]*>(.*?)</\\1>",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern ActionPattern = Pattern.compile("action[\\s]*=[\\s]*(\"|')(.*?)\\1",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern FieldValuePattern = Pattern.compile("value[\\s]*=[\\s]*(\"|')(.*?)\\1",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern FieldNamePattern = Pattern.compile("name[\\s]*=[\\s]*(\"|')(.*?)\\1",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern HiddenFieldPattern = Pattern.compile(
			"<input[^>]*type[^>]*=[^>]*[\"|']hidden[\"|'][^>]*>",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern ContentPattern = Pattern.compile("(\"|')(.*?)\\1",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);

	private static final Pattern ltPattern = Pattern.compile("&lt[;]*",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern gtPattern = Pattern.compile("&gt[;]*",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern ltESCPattern = Pattern.compile("[&%]{1,1}[#xu]*[0]*[63]+[0c]+;*",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern gtESCPattern = Pattern.compile("[&%]{1,1}[#xu]*[0]*[63]+[2e]+;*",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);

	private static final Pattern ESCinTagPattern = Pattern.compile("<(.*[&%]{1,1}[#xu]*[0]*[a-f\\d]+;*.*)*>",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern ESC1Pattern = Pattern.compile("[&%]{1,1}[#xu]*[0]*[a-f\\d]+;*",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern ESC2Pattern = Pattern.compile("\\\\[#xu]*[0]*[a-f\\d]+;*",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern ESC3Pattern = Pattern.compile("/((\\%3C)|<)((\\%2F)|\\/)*[a-z0-9\\%]+((\\%3E)|>)",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);

	private static final Pattern SQL1Pattern = Pattern.compile(
			"/((\\%3D)|(=))[^\n]*((\\%27)|(\')|(\\-\\-)|(\\%3B)|(;))",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern SQL2Pattern = Pattern.compile(
			"/\\w*((\\%27)|(\\'))((\\%6F)|o|(\\%4F))((\\%72)|r|(\\%52))",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
	private static final Pattern SQL3Pattern = Pattern.compile("/exec(\\s|\\+)+(s|x)p\\w+",
			Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);

	private String smEncodingType = new String("UTF-8");

	public smPageFilter() {

	}

	private static String doLinkFilter(String serverName, String inString) {
		Matcher linkMatcher = PageLinkPattern.matcher(inString);
		StringBuffer outString = new StringBuffer("");
		String finds;
		String page = "";
		String params = "";
		String rString = "";
		String delim = "";
		String serverPage;
		String encParams;

		while (linkMatcher.find()) {
			finds = linkMatcher.group();
			page = finds.substring(1, finds.indexOf("?"));
			delim = finds.substring(0, 1);
			params = finds.substring(finds.indexOf("?") + 1, finds.length() - 1);
			rString = delim + page + "?/";
			serverPage = serverName + page;
			// encParams = smEncrypt(params).toString();
			// rString = rString + smThread(serverPage, encParams).toUpperCase();
			rString = rString + delim;
			linkMatcher.appendReplacement(outString, rString);
		}
		linkMatcher.appendTail(outString);
		return (outString.toString());
	}

	private String doXSSFilter(String inString, String TAGS, String KEYS) {
		String utf8String = "";
		String testString = "";
		Pattern tagPattern;

		try {
			utf8String = URLDecoder.decode(inString, this.smEncodingType);
		} catch (UnsupportedEncodingException e) {
			return (inString);
		}

		try {
			while (testString != utf8String) {
				testString = utf8String;
				utf8String = URLDecoder.decode(inString, this.smEncodingType);
			}
		} catch (UnsupportedEncodingException e) {
			return (inString);
		}

		StringBuffer outString = new StringBuffer(utf8String);

		if (TAGS.length() > 0)
			tagPattern = Pattern.compile("<+[^>]*(" + TAGS + ")[^>]*>+",
					Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
		else
			tagPattern = Pattern.compile("<[^>]*>",
					Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE | Pattern.UNICODE_CASE);
		Pattern keyPattern = Pattern.compile("(" + KEYS + ")*");

		final Matcher ltMatcher = ltPattern.matcher(outString);
		if (ltMatcher.find())
			outString = new StringBuffer(ltMatcher.replaceAll("<"));

		final Matcher gtMatcher = gtPattern.matcher(outString);
		if (gtMatcher.find())
			outString = new StringBuffer(gtMatcher.replaceAll(">"));

		final Matcher ltESCMatcher = ltESCPattern.matcher(outString);
		if (ltESCMatcher.find())
			outString = new StringBuffer(ltESCMatcher.replaceAll("<"));

		final Matcher gtESCMatcher = gtESCPattern.matcher(outString);
		if (gtESCMatcher.find())
			outString = new StringBuffer(gtESCMatcher.replaceAll(">"));

		final Matcher ESC1Matcher = ESC1Pattern.matcher(outString);
		if (ESC1Matcher.find())
			outString = new StringBuffer(ESC1Matcher.replaceAll(""));

		final Matcher ESC2Matcher = ESC2Pattern.matcher(outString);
		if (ESC2Matcher.find())
			outString = new StringBuffer(ESC2Matcher.replaceAll(""));

		final Matcher ESC3Matcher = ESC3Pattern.matcher(outString);
		if (ESC3Matcher.find())
			outString = new StringBuffer(ESC3Matcher.replaceAll(""));

		final Matcher ESCinTagMatcher = ESCinTagPattern.matcher(outString);
		if (ESCinTagMatcher.find())
			outString = new StringBuffer(ESCinTagMatcher.replaceAll(""));

		final Matcher SQL1Matcher = SQL1Pattern.matcher(outString);
		if (SQL1Matcher.find())
			outString = new StringBuffer(SQL1Matcher.replaceAll(""));

		final Matcher SQL2Matcher = SQL2Pattern.matcher(outString);
		if (SQL2Matcher.find())
			outString = new StringBuffer(SQL2Matcher.replaceAll(""));

		final Matcher SQL3Matcher = SQL3Pattern.matcher(outString);
		if (SQL3Matcher.find())
			outString = new StringBuffer(SQL3Matcher.replaceAll(""));

		final Matcher tagMatcher = tagPattern.matcher(outString);
		if (tagMatcher.find())
			outString = new StringBuffer(tagMatcher.replaceAll(""));

		final Matcher keyMatcher = keyPattern.matcher(outString);
		if (keyMatcher.find())
			outString = new StringBuffer(keyMatcher.replaceAll(""));

		return (outString.toString());
	}
}
