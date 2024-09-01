package com.thixo.security.securemax;

/**
 * <p>Title: Squid Security Systems</p>
 *
 * <p>Description: Ultimate Java Security for ColdFusion</p>
 *
 * <p>Copyright: Copyright (c) 2005</p>
 *
 * @author Jeff L Greenwell
 * @version 1.0
 */

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Set;
import java.util.HashSet;
import java.util.Iterator;

public class smCryptoListing {
	public smCryptoListing() {
	}

	private static String[] getServiceTypes() {
		Set result = new HashSet();
		Provider[] providers = Security.getProviders();
		for (int i = 0; i < providers.length; i++) {
			Set keys = providers[i].keySet();
			for (Iterator it = keys.iterator(); it.hasNext();) {
				String key = (String) it.next();
				key = key.split(" ")[0];
				if (key.startsWith("Alg.Alias")) {
					key = key.substring(10);
				}
				int ix = key.indexOf('.');
				result.add(key.substring(0, ix));
			}
		}
		return (String[]) result.toArray(new String[result.size()]);
	}

	private static String[] getCryptoImpls(String serviceType) {
		Set result = new HashSet();
		Provider[] providers = Security.getProviders();
		for (int i = 0; i < providers.length; i++) {
			Set keys = providers[i].keySet();
			for (Iterator it = keys.iterator(); it.hasNext();) {
				String key = (String) it.next();
				key = key.split(" ")[0];
				if (key.startsWith(serviceType + ".")) {
					result.add(key.substring(serviceType.length() + 1));
				} else if (key.startsWith("Alg.Alias." + serviceType + ".")) {
					result.add(key.substring(serviceType.length() + 11));
				}
			}
		}
		return (String[]) result.toArray(new String[result.size()]);
	}

	private static void listServiceTypes() {
		System.out.println();
		System.out.println("Service Types");
		System.out.println("-------------");
		String[] serviceTypes = getServiceTypes();
		Arrays.sort(serviceTypes);
		for (int i = 0; i < serviceTypes.length; i++) {
			System.out.println("  - " + serviceTypes[i]);
		}
		System.out.println();
	}

	private static void listCryptoImpls() {
		System.out.println();
		System.out.println("Service Type Implementations");
		System.out.println("----------------------------");
		String[] serviceTypes = getServiceTypes();
		Arrays.sort(serviceTypes);

		for (int i = 0; i < serviceTypes.length; i++) {
			System.out.println();
			System.out.println("  - " + serviceTypes[i]);
			String[] serviceTypeImpls = getCryptoImpls(serviceTypes[i]);
			Arrays.sort(serviceTypeImpls);
			for (int j = 0; j < serviceTypeImpls.length; j++) {
				System.out.println("      " + serviceTypeImpls[j]);
			}
		}
		System.out.println();
	}

	public static void main(String[] args) {
		smCryptoListing clTest = new smCryptoListing();
		clTest.listServiceTypes();
		clTest.listCryptoImpls();
	}

}
