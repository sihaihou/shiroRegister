package com.housihai.shiro.core.commons;

/**
 * 请求头合并规则
 * @author  reyco
 * @date    2022.11.28
 * @version v1.0.1
 */
public class HeadersRequestCondition {
	/**
	 *
	 * @author  reyco
	 * @date    2022年11月30日
	 * @version v1.0.1
	 * @param headers
	 * @param other
	 * @return
	 */
	public static String[] combine(String[] headers,String[] other) {
		String[] result = new String[headers.length+other.length];
		int index = 0;
		for (int i = 0; i < headers.length; i++) {
			result[index++] = headers[i];
		}
		for (int i = 0; i < other.length; i++) {
			result[index++] = other[i];
		}
		return result;
	}
}
